// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package runner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/rs/xid"
	"golang.org/x/crypto/ssh"
	"golang.org/x/sync/errgroup"
	"gopkg.in/yaml.v2"
	"k8s.io/utils/strings/slices"

	"github.com/elastic/elastic-agent/pkg/core/process"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/ess"
)

// OSRunnerPackageResult is the result for each package.
type OSRunnerPackageResult struct {
	// Name is the package name.
	Name string
	// Output is the raw test output.
	Output []byte
	// XMLOutput is the XML Junit output.
	XMLOutput []byte
	// JSONOutput is the JSON output.
	JSONOutput []byte
}

// OSRunnerResult is the result of the test run provided by a OSRunner.
type OSRunnerResult struct {
	// Packages is the results for each package.
	Packages []OSRunnerPackageResult

	// SudoPackages is the results for each package that need to run as sudo.
	SudoPackages []OSRunnerPackageResult
}

// OSRunner provides an interface to run the tests on the OS.
type OSRunner interface {
	// Prepare prepares the runner to actual run on the host.
	Prepare(ctx context.Context, c *ssh.Client, logger Logger, arch string, goVersion string, repoArchive string, buildPath string) error
	// Run runs the actual tests and provides the result.
	Run(ctx context.Context, c *ssh.Client, logger Logger, agentVersion string, prefix string, batch define.Batch, env map[string]string) (OSRunnerResult, error)
}

// Logger is a simple logging interface used by each runner type.
type Logger interface {
	// Prefix returns the prefix used for logging.
	Prefix() string
	// Logf logs the message for this runner.
	Logf(format string, args ...any)
}

// Result is the complete result from the runner.
type Result struct {
	// Tests is the number of tests ran.
	Tests int
	// Failures is the number of tests that failed.
	Failures int
	// Output is the raw test output.
	Output []byte
	// XMLOutput is the XML Junit output.
	XMLOutput []byte
	// JSONOutput is the JSON output.
	JSONOutput []byte
}

// Runner runs the tests on remote instances.
type Runner struct {
	cfg            Config
	batches        []LayoutBatch
	batchToCloud   map[string]*essCloudResponse
	batchToCloudMx sync.RWMutex
}

// NewRunner creates a new runner based on the provided batches.
func NewRunner(cfg Config, batches ...define.Batch) (*Runner, error) {
	err := cfg.Validate()
	if err != nil {
		return nil, err
	}
	var layoutBatches []LayoutBatch
	for _, b := range batches {
		lbs, err := createBatches(b, cfg.Matrix)
		if err != nil {
			return nil, err
		}
		layoutBatches = append(layoutBatches, lbs...)
	}
	if cfg.SingleTest != "" {
		layoutBatches, err = filterSingleTest(layoutBatches, cfg.SingleTest)
		if err != nil {
			return nil, err
		}
	}
	return &Runner{
		cfg:          cfg,
		batches:      layoutBatches,
		batchToCloud: make(map[string]*essCloudResponse),
	}, nil
}

// Run runs all the tests.
func (r *Runner) Run(ctx context.Context) (Result, error) {
	// validate tests can even be performed
	err := r.validate()
	if err != nil {
		return Result{}, err
	}

	// prepare
	prepareCtx, prepareCancel := context.WithTimeout(ctx, 10*time.Minute)
	defer prepareCancel()
	sshAuth, repoArchive, err := r.prepare(prepareCtx)
	if err != nil {
		return Result{}, err
	}

	// initiate the needed clouds
	err = r.setupCloud(ctx)
	if err != nil {
		return Result{}, err
	}
	defer func() {
		// always clean
		r.cleanupCloud()
	}()

	// import the calculated layouts
	importCtx, importCancel := context.WithTimeout(ctx, 30*time.Second)
	defer importCancel()
	err = r.ogcImport(importCtx)
	if err != nil {
		return Result{}, err
	}

	// bring up all the instances
	upCtx, upCancel := context.WithTimeout(ctx, 30*time.Minute)
	defer upCancel()
	upOutput, err := r.ogcUp(upCtx)
	if err != nil {
		return Result{}, err
	}
	defer func() {
		// always clean
		_ = r.Clean()
	}()

	// fetch the machines and run the batches on the machine
	machines, err := r.ogcMachines(ctx)
	if err != nil {
		return Result{}, err
	}
	if len(machines) == 0 {
		// print the output so its clear what went wrong
		// without this it's unclear where OGC went wrong it
		// doesn't do a great job of reporting a clean error
		fmt.Printf("%s\n", upOutput)
		return Result{}, fmt.Errorf("ogc didn't create any machines")
	}
	results, err := r.runMachines(ctx, sshAuth, repoArchive, machines)
	if err != nil {
		return Result{}, err
	}

	// merge the results
	return r.mergeResults(results)
}

// Clean performs a cleanup to ensure anything that could have been left running is removed.
func (r *Runner) Clean() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	return r.ogcDown(ctx)
}

// runMachines runs the batch on each machine in parallel.
func (r *Runner) runMachines(ctx context.Context, sshAuth ssh.AuthMethod, repoArchive string, machines []OGCMachine) (map[string]OSRunnerResult, error) {
	g, ctx := errgroup.WithContext(ctx)
	results := make(map[string]OSRunnerResult)
	var resultsMx sync.Mutex
	for _, m := range machines {
		func(m OGCMachine) {
			g.Go(func() error {
				batch, ok := findLayoutBatchByID(m.Layout.Name, r.batches)
				if !ok {
					return fmt.Errorf("unable to find layout batch with ID: %s", m.Layout.Name)
				}
				loggerPrefix := fmt.Sprintf(
					"%s/%s/%s/%s[%s]",
					batch.LayoutOS.OS.Type,
					batch.LayoutOS.OS.Arch,
					batch.LayoutOS.OS.Distro,
					batch.LayoutOS.OS.Version,
					batch.ID[len(batch.ID)-5:len(batch.ID)-1],
				)
				logger := &batchLogger{prefix: loggerPrefix}
				result, err := r.runMachine(ctx, sshAuth, logger, repoArchive, batch, m)
				if err != nil {
					logger.Logf("Failed for instance %s: %s\n", m.PublicIP, err)
					return err
				}
				resultsMx.Lock()
				results[batch.ID] = result
				resultsMx.Unlock()
				return nil
			})
		}(m)
	}
	err := g.Wait()
	if err != nil {
		return nil, err
	}
	return results, nil
}

// runMachine runs the batch on the machine.
func (r *Runner) runMachine(ctx context.Context, sshAuth ssh.AuthMethod, logger Logger, repoArchive string, batch LayoutBatch, machine OGCMachine) (OSRunnerResult, error) {
	logger.Logf("Starting SSH connection to %s", machine.PublicIP)
	connectCtx, connectCancel := context.WithTimeout(ctx, 10*time.Minute)
	defer connectCancel()
	client, err := sshConnect(connectCtx, machine.PublicIP, machine.Layout.Username, sshAuth)
	if err != nil {
		logger.Logf("Failed to connect to instance %s: %s", machine.PublicIP, err)
		return OSRunnerResult{}, fmt.Errorf("failed to connect to instance %s: %w", machine.InstanceName, err)
	}
	defer client.Close()
	logger.Logf("Connected over SSH")

	// prepare the host to run the tests
	logger.Logf("Preparing instance")
	err = batch.LayoutOS.Runner.Prepare(ctx, client, logger, batch.LayoutOS.OS.Arch, r.cfg.GOVersion, repoArchive, r.getBuildPath(batch))
	if err != nil {
		logger.Logf("Failed to prepare instance: %s", err)
		return OSRunnerResult{}, fmt.Errorf("failed to prepare instance %s: %w", machine.InstanceName, err)
	}

	// ensure that we have all the requirements for the stack if required
	var env map[string]string
	if batch.Batch.Stack != nil {
		ch, err := r.getCloudForBatchID(batch.ID)
		if err != nil {
			return OSRunnerResult{}, err
		}
		logger.Logf("Waiting for stack to be ready")
		resp := <-ch
		if resp == nil {
			logger.Logf("Cannot continue because stack never became ready")
		} else {
			logger.Logf("Will continue stack is ready")
			env = map[string]string{
				"ELASTICSEARCH_HOST":     resp.ElasticsearchEndpoint,
				"ELASTICSEARCH_USERNAME": resp.Username,
				"ELASTICSEARCH_PASSWORD": resp.Password,
				"KIBANA_HOST":            resp.KibanaEndpoint,
				"KIBANA_USERNAME":        resp.Username,
				"KIBANA_PASSWORD":        resp.Password,
			}
		}
	}

	// run the actual tests on the host
	prefix := fmt.Sprintf("%s-%s-%s-%s", batch.LayoutOS.OS.Type, batch.LayoutOS.OS.Arch, batch.LayoutOS.OS.Distro, strings.Replace(batch.LayoutOS.OS.Version, ".", "", -1))
	result, err := batch.LayoutOS.Runner.Run(ctx, client, logger, r.cfg.AgentVersion, prefix, batch.Batch, env)
	if err != nil {
		logger.Logf("Failed to execute tests on instance: %s", err)
		return OSRunnerResult{}, fmt.Errorf("failed to execute tests on instance %s: %w", machine.InstanceName, err)
	}
	return result, nil
}

// validate ensures that required builds of Elastic Agent exist
func (r *Runner) validate() error {
	var requiredFiles []string
	for _, b := range r.batches {
		if !b.Skip {
			buildPath := r.getBuildPath(b)
			if !slices.Contains(requiredFiles, buildPath) {
				requiredFiles = append(requiredFiles, buildPath)
			}
		}
	}
	var missingFiles []string
	for _, file := range requiredFiles {
		_, err := os.Stat(file)
		if os.IsNotExist(err) {
			missingFiles = append(missingFiles, file)
		} else if err != nil {
			return err
		}
	}
	if len(missingFiles) > 0 {
		return fmt.Errorf("missing required Elastic Agent package builds for integration runner to execute: %s", strings.Join(missingFiles, ", "))
	}
	return nil
}

// getBuildPath returns the path of the build required for the test.
func (r *Runner) getBuildPath(b LayoutBatch) string {
	arch := b.LayoutOS.OS.Arch
	if arch == define.AMD64 {
		arch = "x86_64"
	}
	ext := "tar.gz"
	if b.LayoutOS.OS.Type == define.Windows {
		ext = "zip"
	}
	return filepath.Join(r.cfg.BuildDir, fmt.Sprintf("elastic-agent-%s-%s-%s.%s", r.cfg.AgentVersion, b.LayoutOS.OS.Type, arch, ext))
}

// prepare prepares for the runner to run.
//
// Creates the SSH keys to use, creates the archive of the repo and pulls the latest container for OGC.
func (r *Runner) prepare(ctx context.Context) (ssh.AuthMethod, string, error) {
	wd, err := r.getWorkDir()
	if err != nil {
		return nil, "", err
	}
	cacheDir := filepath.Join(wd, ".ogc-cache")
	_, err = os.Stat(cacheDir)
	if errors.Is(err, os.ErrNotExist) {
		err = os.Mkdir(cacheDir, 0755)
		if err != nil {
			return nil, "", fmt.Errorf("failed to create %q: %w", cacheDir, err)
		}
	} else if err != nil {
		// unknown error
		return nil, "", err
	}

	var auth ssh.AuthMethod
	var repoArchive string
	g, gCtx := errgroup.WithContext(ctx)
	g.Go(func() error {
		a, err := r.createSSHKey(cacheDir)
		if err != nil {
			return err
		}
		auth = a
		return nil
	})
	g.Go(func() error {
		repo, err := r.createRepoArchive(ctx, r.cfg.RepoDir, cacheDir)
		if err != nil {
			return err
		}
		repoArchive = repo
		return nil
	})
	g.Go(func() error {
		return r.ogcPull(gCtx)
	})
	err = g.Wait()
	if err != nil {
		return nil, "", err
	}
	return auth, repoArchive, err
}

// createSSHKey creates the required SSH keys
func (r *Runner) createSSHKey(dir string) (ssh.AuthMethod, error) {
	privateKey := filepath.Join(dir, "id_rsa")
	_, priErr := os.Stat(privateKey)
	publicKey := filepath.Join(dir, "id_rsa.pub")
	_, pubErr := os.Stat(publicKey)
	var signer ssh.Signer
	if errors.Is(priErr, os.ErrNotExist) || errors.Is(pubErr, os.ErrNotExist) {
		// either is missing (re-create)
		fmt.Printf(">>> Create SSH keys to use for SSH\n")
		_ = os.Remove(privateKey)
		_ = os.Remove(publicKey)
		pri, err := newSSHPrivateKey()
		if err != nil {
			return nil, fmt.Errorf("failed to create ssh private key: %w", err)
		}
		pubBytes, err := newSSHPublicKey(&pri.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("failed to create ssh public key: %w", err)
		}
		priBytes := sshEncodeToPEM(pri)
		err = os.WriteFile(privateKey, priBytes, 0600)
		if err != nil {
			return nil, fmt.Errorf("failed to write ssh private key: %w", err)
		}
		err = os.WriteFile(publicKey, pubBytes, 0644)
		if err != nil {
			return nil, fmt.Errorf("failed to write ssh public key: %w", err)
		}
		signer, err = ssh.ParsePrivateKey(priBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse ssh private key: %w", err)
		}
	} else if priErr != nil {
		// unknown error
		return nil, priErr
	} else if pubErr != nil {
		// unknown error
		return nil, pubErr
	} else {
		// read from existing private key
		priBytes, err := os.ReadFile(privateKey)
		if err != nil {
			return nil, fmt.Errorf("failed to read ssh private key %s: %w", privateKey, err)
		}
		signer, err = ssh.ParsePrivateKey(priBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse ssh private key: %w", err)
		}
	}
	return ssh.PublicKeys(signer), nil
}

func (r *Runner) createRepoArchive(ctx context.Context, repoDir string, dir string) (string, error) {
	zipPath := filepath.Join(dir, "agent-repo.zip")
	_ = os.Remove(zipPath) // start fresh
	fmt.Printf(">>> Creating zip archive of repo to send to remote hosts\n")
	err := createRepoZipArchive(ctx, repoDir, zipPath)
	if err != nil {
		return "", fmt.Errorf("failed to create zip archive of repo: %w", err)
	}
	return zipPath, nil
}

// ogcPull pulls the latest ogc version.
func (r *Runner) ogcPull(ctx context.Context) error {
	args := []string{
		"pull",
		"docker.io/gorambo/ogc:latest",
	}
	fmt.Printf(">>> Pulling latest ogc image\n")
	proc, err := process.Start("docker", process.WithContext(ctx), process.WithArgs(args))
	if err != nil {
		return fmt.Errorf("failed to run docker pull: %w", err)
	}
	ps := <-proc.Wait()
	if ps.ExitCode() != 0 {
		return fmt.Errorf("failed to run ogc import: docker run exited with code: %d", ps.ExitCode())
	}
	return nil
}

// setupCloud creates the clouds required for the tests to run
func (r *Runner) setupCloud(ctx context.Context) error {
	var versions []string
	batchToVersion := make(map[string]string)
	for _, lb := range r.batches {
		if !lb.Skip && lb.Batch.Stack != nil {
			if lb.Batch.Stack.Version == "" {
				// no version defined on the stack; set it to the defined stack version
				lb.Batch.Stack.Version = r.cfg.AgentStackVersion
			}
			if !slices.Contains(versions, lb.Batch.Stack.Version) {
				versions = append(versions, lb.Batch.Stack.Version)
			}
			batchToVersion[lb.ID] = lb.Batch.Stack.Version
		}
	}
	// use GCE email to add uniqueness to deployment names
	email, err := r.cfg.GCE.ClientEmail()
	if err != nil {
		return err
	}
	emailParts := strings.Split(email, "@")
	essClient := ess.NewClient(ess.Config{
		ApiKey: r.cfg.ESS.APIKey,
	})
	r.batchToCloudMx.Lock()
	defer r.batchToCloudMx.Unlock()
	for _, version := range versions {
		name := fmt.Sprintf("at-%s-%s", strings.Replace(emailParts[0], ".", "-", -1), strings.Replace(version, ".", "", -1))
		fmt.Printf(">>> Creating ESS cloud %s (%s)\n", version, name)
		resp, err := essClient.CreateDeployment(ctx, ess.CreateDeploymentRequest{
			Name:    name,
			Region:  r.cfg.ESS.Region,
			Version: version,
		})
		if err != nil {
			fmt.Printf(">>> Failed to create ESS cloud %s: %s\n", version, err)
			return fmt.Errorf("failed to create ESS cloud for version %s: %w", version, err)
		}
		essResp := &essCloudResponse{
			resp:  resp,
			ready: false,
			subCh: nil,
		}
		for batchID, batchVersion := range batchToVersion {
			if batchVersion == version {
				r.batchToCloud[batchID] = essResp
			}
		}
		go func(ctx context.Context, version string, resp *essCloudResponse) {
			ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
			defer cancel()
			ready, err := essClient.DeploymentIsReady(ctx, resp.resp.ID, 30*time.Second)
			if err != nil {
				fmt.Printf(">>> Failed to check for cloud %s to be ready: %s\n", version, err)
			}
			resp.subMx.RLock()
			subs := make([]chan *ess.CreateDeploymentResponse, len(resp.subCh))
			copy(subs, resp.subCh)
			resp.subCh = make([]chan *ess.CreateDeploymentResponse, 0)
			resp.done = true
			resp.ready = ready
			resp.subMx.RUnlock()
			var send *ess.CreateDeploymentResponse
			if ready {
				send = resp.resp
			}
			for _, sub := range subs {
				select {
				case <-ctx.Done():
					return
				case sub <- send:
				}
			}
		}(ctx, version, essResp)
	}
	return nil
}

func (r *Runner) cleanupCloud() {
	r.batchToCloudMx.Lock()
	defer r.batchToCloudMx.Unlock()

	essClient := ess.NewClient(ess.Config{
		ApiKey: r.cfg.ESS.APIKey,
	})

	var removed []string
	for _, cloud := range r.batchToCloud {
		if slices.Contains(removed, cloud.resp.ID) {
			// already removed
			continue
		}
		removed = append(removed, cloud.resp.ID)
		err := func() error {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			return essClient.ShutdownDeployment(ctx, cloud.resp.ID)
		}()
		if err != nil {
			fmt.Printf(">>> Failed to cleanup cloud %s: %s\n", cloud.resp.ID, err)
		}
	}

	r.batchToCloud = make(map[string]*essCloudResponse)
}

func (r *Runner) getCloudForBatchID(id string) (chan *ess.CreateDeploymentResponse, error) {
	r.batchToCloudMx.RLock()
	essResp, ok := r.batchToCloud[id]
	if !ok {
		r.batchToCloudMx.RUnlock()
		return nil, fmt.Errorf("no batch with ID %s", id)
	}
	r.batchToCloudMx.RUnlock()

	essResp.subMx.RLock()
	subCh := make(chan *ess.CreateDeploymentResponse, 1)
	if essResp.done {
		if essResp.ready {
			subCh <- essResp.resp
		} else {
			subCh <- nil
		}
		essResp.subMx.RUnlock()
		return subCh, nil
	}
	essResp.subMx.RUnlock()
	essResp.subMx.Lock()
	essResp.subCh = append(essResp.subCh, subCh)
	essResp.subMx.Unlock()
	return subCh, nil
}

// ogcImport imports all the required batches into OGC.
func (r *Runner) ogcImport(ctx context.Context) error {
	var layouts []OGCLayout
	for _, lb := range r.batches {
		if !lb.Skip {
			layouts = append(layouts, lb.toOGC())
		}
	}
	layoutData, err := yaml.Marshal(struct {
		Layouts []OGCLayout `yaml:"layouts"`
	}{
		Layouts: layouts,
	})
	if err != nil {
		return fmt.Errorf("failed to marshal layouts YAML: %w", err)
	}
	fmt.Printf(">>> Import layouts into ogc\n")
	proc, err := r.ogcRun(ctx, []string{"layout", "import"}, true)
	if err != nil {
		return fmt.Errorf("failed to run ogc import: %w", err)
	}
	_, err = proc.Stdin.Write(layoutData)
	if err != nil {
		_ = proc.Stdin.Close()
		_ = proc.Kill()
		<-proc.Wait()
		return fmt.Errorf("failed to write layouts to stdin: %w", err)
	}
	_ = proc.Stdin.Close()
	ps := <-proc.Wait()
	if ps.ExitCode() != 0 {
		return fmt.Errorf("failed to run ogc import: docker run exited with code: %d", ps.ExitCode())
	}
	return nil
}

// ogcUp brings up all the instances.
func (r *Runner) ogcUp(ctx context.Context) ([]byte, error) {
	fmt.Printf(">>> Bring up instances through ogc\n")
	var output bytes.Buffer
	proc, err := r.ogcRun(ctx, []string{"up", LayoutIntegrationTag}, false, process.WithCmdOptions(attachOut(&output), attachErr(&output)))
	if err != nil {
		return nil, fmt.Errorf("failed to run ogc up: %w", err)
	}
	ps := <-proc.Wait()
	if ps.ExitCode() != 0 {
		// print the output so its clear what went wrong
		fmt.Printf("%s\n", output.Bytes())
		return nil, fmt.Errorf("failed to run ogc up: docker run exited with code: %d", ps.ExitCode())
	}
	return output.Bytes(), nil
}

// ogcDown brings down all the instances.
func (r *Runner) ogcDown(ctx context.Context) error {
	fmt.Printf(">>> Bring down instances through ogc\n")
	proc, err := r.ogcRun(ctx, []string{"down", LayoutIntegrationTag}, false)
	if err != nil {
		return fmt.Errorf("failed to run ogc down: %w", err)
	}
	ps := <-proc.Wait()
	if ps.ExitCode() != 0 {
		return fmt.Errorf("failed to run ogc down: docker run exited with code: %d", ps.ExitCode())
	}
	return nil
}

// ogcMachines lists all the instances.
func (r *Runner) ogcMachines(ctx context.Context) ([]OGCMachine, error) {
	var out bytes.Buffer
	proc, err := r.ogcRun(ctx, []string{"ls", "--as-yaml"}, false, process.WithCmdOptions(attachOut(&out)))
	if err != nil {
		return nil, fmt.Errorf("failed to run ogc ls: %w", err)
	}
	ps := <-proc.Wait()
	if ps.ExitCode() != 0 {
		return nil, fmt.Errorf("failed to run ogc ls: docker run exited with code: %d", ps.ExitCode())
	}
	var machines []OGCMachine
	err = yaml.Unmarshal(out.Bytes(), &machines)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ogc ls output: %w", err)
	}
	return machines, nil
}

func (r *Runner) ogcRun(ctx context.Context, args []string, interactive bool, processOpts ...process.StartOption) (*process.Info, error) {
	wd, err := r.getWorkDir()
	if err != nil {
		return nil, err
	}
	tokenName := filepath.Base(r.cfg.GCE.ServiceTokenPath)
	clientEmail, err := r.cfg.GCE.ClientEmail()
	if err != nil {
		return nil, err
	}
	projectID, err := r.cfg.GCE.ProjectID()
	if err != nil {
		return nil, err
	}
	runArgs := []string{"run"}
	if interactive {
		runArgs = append(runArgs, "-i")
	}
	runArgs = append(runArgs,
		"--rm",
		"-e",
		fmt.Sprintf("GOOGLE_APPLICATION_SERVICE_ACCOUNT=%s", clientEmail),
		"-e",
		fmt.Sprintf("GOOGLE_APPLICATION_CREDENTIALS=/root/%s", tokenName),
		"-e",
		fmt.Sprintf("GOOGLE_PROJECT=%s", projectID),
		"-e",
		fmt.Sprintf("GOOGLE_DATACENTER=%s", r.cfg.GCE.Datacenter),
		"-v",
		fmt.Sprintf("%s:/root/%s", r.cfg.GCE.ServiceTokenPath, tokenName),
		"-v",
		fmt.Sprintf("%s:%s", wd, wd),
		"-w",
		wd,
		"docker.io/gorambo/ogc:latest",
		"--",
		"ogc",
		"-v",
	)
	runArgs = append(runArgs, args...)
	opts := []process.StartOption{process.WithContext(ctx), process.WithArgs(runArgs)}
	opts = append(opts, processOpts...)
	return process.Start("docker", opts...)
}

func (r *Runner) getWorkDir() (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("failed to get work directory: %w", err)
	}
	wd, err = filepath.Abs(wd)
	if err != nil {
		return "", fmt.Errorf("failed to get absolute path to work directory: %w", err)
	}
	return wd, nil
}

func (r *Runner) mergeResults(results map[string]OSRunnerResult) (Result, error) {
	var rawOutput bytes.Buffer
	var jsonOutput bytes.Buffer
	var suites JUnitTestSuites
	for id, res := range results {
		batch, ok := findLayoutBatchByID(id, r.batches)
		if !ok {
			return Result{}, fmt.Errorf("batch ID not found %s", id)
		}
		batchName := fmt.Sprintf("%s/%s/%s/%s", batch.LayoutOS.OS.Type, batch.LayoutOS.OS.Arch, batch.LayoutOS.OS.Distro, batch.LayoutOS.OS.Version)
		for _, pkg := range res.Packages {
			err := mergePackageResult(pkg, id, batchName, false, &rawOutput, &jsonOutput, &suites)
			if err != nil {
				return Result{}, err
			}
		}
		for _, pkg := range res.SudoPackages {
			err := mergePackageResult(pkg, id, batchName, true, &rawOutput, &jsonOutput, &suites)
			if err != nil {
				return Result{}, err
			}
		}
	}
	var junitBytes bytes.Buffer
	err := writeJUnit(&junitBytes, suites)
	if err != nil {
		return Result{}, fmt.Errorf("failed to marshal junit: %w", err)
	}

	var complete Result
	for _, suite := range suites.Suites {
		complete.Tests += suite.Tests
		complete.Failures += suite.Failures
	}
	complete.Output = rawOutput.Bytes()
	complete.JSONOutput = jsonOutput.Bytes()
	complete.XMLOutput = junitBytes.Bytes()
	return complete, nil
}

func mergePackageResult(pkg OSRunnerPackageResult, id string, batchName string, sudo bool, rawOutput io.Writer, jsonOutput io.Writer, suites *JUnitTestSuites) error {
	suffix := ""
	sudoStr := "false"
	if sudo {
		suffix = "(sudo)"
		sudoStr = "true"
	}
	if pkg.Output != nil {
		pkgWriter := newPrefixOutput(rawOutput, fmt.Sprintf("%s(%s)%s: ", pkg.Name, batchName, suffix))
		_, err := pkgWriter.Write(pkg.Output)
		if err != nil {
			return fmt.Errorf("failed to write raw output from %s %s: %w", id, pkg.Name, err)
		}
	}
	if pkg.JSONOutput != nil {
		jsonSuffix, err := suffixJSONResults(pkg.JSONOutput, fmt.Sprintf("(%s)%s", batchName, suffix))
		if err != nil {
			return fmt.Errorf("failed to suffix json output from %s %s: %w", id, pkg.Name, err)
		}
		_, err = jsonOutput.Write(jsonSuffix)
		if err != nil {
			return fmt.Errorf("failed to write json output from %s %s: %w", id, pkg.Name, err)
		}
	}
	if pkg.XMLOutput != nil {
		pkgSuites, err := parseJUnit(pkg.XMLOutput)
		if err != nil {
			return fmt.Errorf("failed to parse junit from %s %s: %w", id, pkg.Name, err)
		}
		for _, pkgSuite := range pkgSuites.Suites {
			// append the batch information to the suite name
			pkgSuite.Name = fmt.Sprintf("%s(%s)%s", pkgSuite.Name, batchName, suffix)
			pkgSuite.Properties = append(pkgSuite.Properties, JUnitProperty{
				Name:  "batch",
				Value: batchName,
			}, JUnitProperty{
				Name:  "sudo",
				Value: sudoStr,
			})
			suites.Suites = append(suites.Suites, pkgSuite)
		}
	}
	return nil
}

func attachOut(w io.Writer) process.CmdOption {
	return func(c *exec.Cmd) error {
		c.Stdout = w
		return nil
	}
}

func attachErr(w io.Writer) process.CmdOption {
	return func(c *exec.Cmd) error {
		c.Stderr = w
		return nil
	}
}

func findLayoutBatchByID(id string, batches []LayoutBatch) (LayoutBatch, bool) {
	for _, batch := range batches {
		if batch.ID == id {
			return batch, true
		}
	}
	return LayoutBatch{}, false
}

func createBatches(batch define.Batch, matrix bool) ([]LayoutBatch, error) {
	var batches []LayoutBatch
	specifics, err := getSupported(batch.OS)
	if errors.Is(err, ErrOSNotSupported) {
		var s LayoutOS
		s.OS.Type = batch.OS.Type
		s.OS.Arch = batch.OS.Arch
		s.OS.Distro = batch.OS.Distro
		if s.OS.Distro == "" {
			s.OS.Distro = "unknown"
		}
		if s.OS.Version == "" {
			s.OS.Version = "unknown"
		}
		batches = append(batches, LayoutBatch{
			ID:       xid.New().String(),
			LayoutOS: s,
			Batch:    batch,
			Skip:     true,
		})
		return batches, nil
	} else if err != nil {
		return nil, err
	}
	if matrix {
		for _, s := range specifics {
			batches = append(batches, LayoutBatch{
				ID:       xid.New().String(),
				LayoutOS: s,
				Batch:    batch,
				Skip:     false,
			})
		}
	} else {
		batches = append(batches, LayoutBatch{
			ID:       xid.New().String(),
			LayoutOS: specifics[0],
			Batch:    batch,
			Skip:     false,
		})
	}
	return batches, nil
}

func filterSingleTest(batches []LayoutBatch, singleTest string) ([]LayoutBatch, error) {
	var filtered []LayoutBatch
	for _, batch := range batches {
		batch, ok := filterSingleTestBatch(batch, singleTest)
		if ok {
			filtered = append(filtered, batch)
		}
	}
	if len(filtered) == 0 {
		return nil, fmt.Errorf("test not found: %s", singleTest)
	}
	return filtered, nil
}

func filterSingleTestBatch(batch LayoutBatch, testName string) (LayoutBatch, bool) {
	for _, pt := range batch.Batch.Tests {
		for _, t := range pt.Tests {
			if t == testName {
				// filter batch to only run one test
				batch.Batch.Tests = []define.BatchPackageTests{
					{
						Name:  pt.Name,
						Tests: []string{testName},
					},
				}
				batch.Batch.SudoTests = nil
				return batch, true
			}
		}
	}
	for _, pt := range batch.Batch.SudoTests {
		for _, t := range pt.Tests {
			if t == testName {
				// filter batch to only run one test
				batch.Batch.SudoTests = []define.BatchPackageTests{
					{
						Name:  pt.Name,
						Tests: []string{testName},
					},
				}
				batch.Batch.Tests = nil
				return batch, true
			}
		}
	}
	return batch, false
}

type essCloudResponse struct {
	resp  *ess.CreateDeploymentResponse
	ready bool
	done  bool
	subCh []chan *ess.CreateDeploymentResponse
	subMx sync.RWMutex
}

type batchLogger struct {
	prefix string
}

func (b *batchLogger) Prefix() string {
	return b.prefix
}

func (b *batchLogger) Logf(format string, args ...any) {
	fmt.Printf(">>> (%s) %s\n", b.prefix, fmt.Sprintf(format, args...))
}
