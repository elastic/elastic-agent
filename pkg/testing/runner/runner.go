// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package runner

import (
	"bytes"
	"context"
	"crypto/md5"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"gopkg.in/yaml.v2"

	"golang.org/x/crypto/ssh"
	"golang.org/x/sync/errgroup"
	"k8s.io/utils/strings/slices"

	"github.com/elastic/elastic-agent/pkg/testing/define"
)

// OSBatch defines the mapping between a SupportedOS and a define.Batch.
type OSBatch struct {
	// ID is the unique ID for the batch.
	ID string
	// LayoutOS provides all the OS information to create an instance.
	OS SupportedOS
	// Batch defines the batch of tests to run on this layout.
	Batch define.Batch
	// Skip defines if this batch will be skipped because no supported layout exists yet.
	Skip bool
}

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
	Prepare(ctx context.Context, sshClient SSHClient, logger Logger, arch string, goVersion string) error
	// Copy places the required files on the host.
	Copy(ctx context.Context, sshClient SSHClient, logger Logger, repoArchive string, build Build) error
	// Run runs the actual tests and provides the result.
	Run(ctx context.Context, verbose bool, sshClient SSHClient, logger Logger, agentVersion string, prefix string, batch define.Batch, env map[string]string) (OSRunnerResult, error)
	// Diagnostics gathers any diagnostics from the host.
	Diagnostics(ctx context.Context, sshClient SSHClient, logger Logger, destination string) error
}

// Logger is a simple logging interface used by each runner type.
type Logger interface {
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

// State represents the state storage of what has been provisioned.
type State struct {
	// Instances stores provisioned and prepared instances.
	Instances []StateInstance `yaml:"instances"`

	// Stacks store provisioned stacks.
	Stacks []Stack `yaml:"stacks"`
}

// StateInstance is an instance stored in the state.
type StateInstance struct {
	Instance

	// Prepared set to true when the instance is prepared.
	Prepared bool `yaml:"prepared"`
}

// Build describes a build and its paths.
type Build struct {
	// Version of the Elastic Agent build.
	Version string
	// Type of OS this build is for.
	Type string
	// Arch is architecture this build is for.
	Arch string
	// Path is the path to the build.
	Path string
	// SHA512 is the path to the SHA512 file.
	SHA512Path string
}

// Runner runs the tests on remote instances.
type Runner struct {
	cfg    Config
	logger Logger
	ip     InstanceProvisioner
	sp     StackProvisioner

	batches []OSBatch

	batchToStack   map[string]stackRes
	batchToStackCh map[string]chan stackRes
	batchToStackMx sync.Mutex

	stateMx sync.Mutex
	state   State
}

// NewRunner creates a new runner based on the provided batches.
func NewRunner(cfg Config, ip InstanceProvisioner, sp StackProvisioner, batches ...define.Batch) (*Runner, error) {
	err := cfg.Validate()
	if err != nil {
		return nil, err
	}
	platforms, err := cfg.GetPlatforms()
	if err != nil {
		return nil, err
	}

	logger := &runnerLogger{
		writer:    os.Stdout,
		timestamp: cfg.Timestamp,
	}
	ip.SetLogger(logger)
	sp.SetLogger(logger)

	var osBatches []OSBatch
	for _, b := range batches {
		lbs, err := createBatches(b, platforms, cfg.Groups, cfg.Matrix)
		if err != nil {
			return nil, err
		}
		if lbs != nil {
			osBatches = append(osBatches, lbs...)
		}
	}
	if cfg.SingleTest != "" {
		osBatches, err = filterSingleTest(osBatches, cfg.SingleTest)
		if err != nil {
			return nil, err
		}
	}
	osBatches = filterSupportedOS(osBatches, ip)

	r := &Runner{
		cfg:            cfg,
		logger:         logger,
		ip:             ip,
		sp:             sp,
		batches:        osBatches,
		batchToStack:   make(map[string]stackRes),
		batchToStackCh: make(map[string]chan stackRes),
	}

	err = r.loadState()
	if err != nil {
		return nil, err
	}
	return r, nil
}

// Logger returns the logger used by the runner.
func (r *Runner) Logger() Logger {
	return r.logger
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

	// start the needed stacks
	err = r.startStacks(ctx)
	if err != nil {
		return Result{}, err
	}

	// only send to the provisioner the batches that need to be created
	var instances []StateInstance
	var batches []OSBatch
	for _, b := range r.batches {
		if !b.Skip {
			i, ok := r.findInstance(b.ID)
			if ok {
				instances = append(instances, i)
			} else {
				batches = append(batches, b)
			}
		}
	}
	if len(batches) > 0 {
		provisionedInstances, err := r.ip.Provision(ctx, r.cfg, batches)
		if err != nil {
			return Result{}, err
		}
		for _, i := range provisionedInstances {
			instances = append(instances, StateInstance{
				Instance: i,
				Prepared: false,
			})
		}
	}

	// use SSH to perform all the required work on the instances
	results, err := r.runInstances(ctx, sshAuth, repoArchive, instances)
	if err != nil {
		return Result{}, err
	}

	// merge the results
	return r.mergeResults(results)
}

// Clean performs a cleanup to ensure anything that could have been left running is removed.
func (r *Runner) Clean() error {
	r.stateMx.Lock()
	defer r.stateMx.Unlock()

	var instances []Instance
	for _, i := range r.state.Instances {
		instances = append(instances, i.Instance)
	}
	r.state.Instances = nil
	stacks := make([]Stack, len(r.state.Stacks))
	copy(stacks, r.state.Stacks)
	r.state.Stacks = nil
	err := r.writeState()
	if err != nil {
		return err
	}

	var g errgroup.Group
	g.Go(func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()
		return r.ip.Clean(ctx, r.cfg, instances)
	})
	for _, stack := range stacks {
		g.Go(func(stack Stack) func() error {
			return func() error {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
				defer cancel()
				return r.sp.Delete(ctx, stack)
			}
		}(stack))
	}
	return g.Wait()
}

// runInstances runs the batch on each instance in parallel.
func (r *Runner) runInstances(ctx context.Context, sshAuth ssh.AuthMethod, repoArchive string, instances []StateInstance) (map[string]OSRunnerResult, error) {
	g, ctx := errgroup.WithContext(ctx)
	results := make(map[string]OSRunnerResult)
	var resultsMx sync.Mutex
	for _, i := range instances {
		func(i StateInstance) {
			g.Go(func() error {
				batch, ok := findBatchByID(i.ID, r.batches)
				if !ok {
					return fmt.Errorf("unable to find batch with ID: %s", i.ID)
				}
				logger := &batchLogger{wrapped: r.logger, prefix: i.ID}
				result, err := r.runInstance(ctx, sshAuth, logger, repoArchive, batch, i)
				if err != nil {
					logger.Logf("Failed for instance %s (@ %s): %s\n", i.ID, i.IP, err)
					return err
				}
				resultsMx.Lock()
				results[batch.ID] = result
				resultsMx.Unlock()
				return nil
			})
		}(i)
	}
	err := g.Wait()
	if err != nil {
		return nil, err
	}
	return results, nil
}

// runInstance runs the batch on the machine.
func (r *Runner) runInstance(ctx context.Context, sshAuth ssh.AuthMethod, logger Logger, repoArchive string, batch OSBatch, instance StateInstance) (OSRunnerResult, error) {
	sshPrivateKeyPath, err := filepath.Abs(filepath.Join(r.cfg.StateDir, "id_rsa"))
	if err != nil {
		return OSRunnerResult{}, fmt.Errorf("failed to determine OGC SSH private key path: %w", err)
	}

	logger.Logf("Starting SSH; connect with `ssh -i %s %s@%s`", sshPrivateKeyPath, instance.Username, instance.IP)
	client := NewSSHClient(instance.IP, instance.Username, sshAuth)
	connectCtx, connectCancel := context.WithTimeout(ctx, 10*time.Minute)
	defer connectCancel()
	err = client.Connect(connectCtx)
	if err != nil {
		logger.Logf("Failed to connect to instance %s: %s", instance.IP, err)
		return OSRunnerResult{}, fmt.Errorf("failed to connect to instance %s: %w", instance.Name, err)
	}
	defer client.Close()
	logger.Logf("Connected over SSH")

	if !instance.Prepared {
		// prepare the host to run the tests
		logger.Logf("Preparing instance")
		err = batch.OS.Runner.Prepare(ctx, client, logger, batch.OS.Arch, r.cfg.GOVersion)
		if err != nil {
			logger.Logf("Failed to prepare instance: %s", err)
			return OSRunnerResult{}, fmt.Errorf("failed to prepare instance %s: %w", instance.Name, err)
		}

		// now its prepared, add to state
		instance.Prepared = true
		err = r.addOrUpdateInstance(instance)
		if err != nil {
			return OSRunnerResult{}, fmt.Errorf("failed to save instance state %s: %w", instance.Name, err)
		}
	}

	// copy the required files (done every run)
	err = batch.OS.Runner.Copy(ctx, client, logger, repoArchive, r.getBuild(batch))
	if err != nil {
		logger.Logf("Failed to copy files instance: %s", err)
		return OSRunnerResult{}, fmt.Errorf("failed to copy files to instance %s: %w", instance.Name, err)
	}

	// start with the ExtraEnv first preventing the other environment flags below
	// from being overwritten
	env := map[string]string{}
	for k, v := range r.cfg.ExtraEnv {
		env[k] = v
	}

	// ensure that we have all the requirements for the stack if required
	if batch.Batch.Stack != nil {
		// wait for the stack to be ready before continuing
		logger.Logf("Waiting for stack to be ready...")
		stack, err := r.getStackForBatchID(batch.ID)
		if err != nil {
			return OSRunnerResult{}, err
		}
		env["ELASTICSEARCH_HOST"] = stack.Elasticsearch
		env["ELASTICSEARCH_USERNAME"] = stack.Username
		env["ELASTICSEARCH_PASSWORD"] = stack.Password
		env["KIBANA_HOST"] = stack.Kibana
		env["KIBANA_USERNAME"] = stack.Username
		env["KIBANA_PASSWORD"] = stack.Password
		logger.Logf("Using Stack with Kibana host %s, %s/%s", stack.Kibana, stack.Username, stack.Password)
	}

	// set the go test flags
	env["GOTEST_FLAGS"] = r.cfg.TestFlags

	// run the actual tests on the host
	result, err := batch.OS.Runner.Run(ctx, r.cfg.VerboseMode, client, logger, r.cfg.AgentVersion, batch.ID, batch.Batch, env)
	if err != nil {
		logger.Logf("Failed to execute tests on instance: %s", err)
		return OSRunnerResult{}, fmt.Errorf("failed to execute tests on instance %s: %w", instance.Name, err)
	}

	// fetch any diagnostics
	if r.cfg.DiagnosticsDir != "" {
		err = batch.OS.Runner.Diagnostics(ctx, client, logger, r.cfg.DiagnosticsDir)
		if err != nil {
			logger.Logf("Failed to fetch diagnostics: %s", err)
		}
	} else {
		logger.Logf("Skipping diagnostics fetch as DiagnosticsDir was not set")
	}

	return result, nil
}

// validate ensures that required builds of Elastic Agent exist
func (r *Runner) validate() error {
	var requiredFiles []string
	for _, b := range r.batches {
		if !b.Skip {
			build := r.getBuild(b)
			if !slices.Contains(requiredFiles, build.Path) {
				requiredFiles = append(requiredFiles, build.Path)
			}
			if !slices.Contains(requiredFiles, build.SHA512Path) {
				requiredFiles = append(requiredFiles, build.SHA512Path)
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

// getBuild returns the build for the batch.
func (r *Runner) getBuild(b OSBatch) Build {
	arch := b.OS.Arch
	if arch == define.AMD64 {
		arch = "x86_64"
	}
	ext := "tar.gz"
	if b.OS.Type == define.Windows {
		ext = "zip"
	}
	hashExt := ".sha512"
	packageName := filepath.Join(r.cfg.BuildDir, fmt.Sprintf("elastic-agent-%s-%s-%s.%s", r.cfg.AgentVersion, b.OS.Type, arch, ext))
	return Build{
		Version:    r.cfg.AgentVersion,
		Type:       b.OS.Type,
		Arch:       arch,
		Path:       packageName,
		SHA512Path: packageName + hashExt,
	}
}

// prepare prepares for the runner to run.
//
// Creates the SSH keys to use, creates the archive of the repo and pulls the latest container for OGC.
func (r *Runner) prepare(ctx context.Context) (ssh.AuthMethod, string, error) {
	wd, err := WorkDir()
	if err != nil {
		return nil, "", err
	}
	cacheDir := filepath.Join(wd, r.cfg.StateDir)
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
		repo, err := r.createRepoArchive(gCtx, r.cfg.RepoDir, cacheDir)
		if err != nil {
			return err
		}
		repoArchive = repo
		return nil
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
		r.logger.Logf("Create SSH keys to use for SSH")
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
	r.logger.Logf("Creating zip archive of repo to send to remote hosts")
	err := createRepoZipArchive(ctx, repoDir, zipPath)
	if err != nil {
		return "", fmt.Errorf("failed to create zip archive of repo: %w", err)
	}
	return zipPath, nil
}

// startStacks starts the stacks required for the tests to run
func (r *Runner) startStacks(ctx context.Context) error {
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

	var requests []stackReq
	for _, version := range versions {
		id := strings.Replace(version, ".", "", -1)
		stack, ok := r.findStack(id)
		if ok {
			requests = append(requests, stackReq{
				request: StackRequest{
					ID:      id,
					Version: version,
				},
				stack: &stack,
			})
		} else {
			requests = append(requests, stackReq{
				request: StackRequest{
					ID:      id,
					Version: version,
				},
			})
		}
	}

	reportResult := func(version string, stack Stack, err error) {
		r.batchToStackMx.Lock()
		defer r.batchToStackMx.Unlock()
		res := stackRes{
			stack: stack,
			err:   err,
		}
		for batchID, batchVersion := range batchToVersion {
			if batchVersion == version {
				r.batchToStack[batchID] = res
				ch, ok := r.batchToStackCh[batchID]
				if ok {
					ch <- res
				}
			}
		}
	}

	// start goroutines to provision the needed stacks
	for _, request := range requests {
		go func(ctx context.Context, req stackReq) {
			var err error
			var stack Stack
			if req.stack != nil {
				stack = *req.stack
			} else {
				stack, err = r.sp.Create(ctx, req.request)
				if err != nil {
					reportResult(req.request.Version, stack, err)
					return
				}
				err = r.addOrUpdateStack(stack)
				if err != nil {
					reportResult(stack.Version, stack, err)
					return
				}
			}

			if stack.Ready {
				reportResult(stack.Version, stack, nil)
				return
			}

			stack, err = r.sp.WaitForReady(ctx, stack)
			if err != nil {
				reportResult(stack.Version, stack, err)
				return
			}

			err = r.addOrUpdateStack(stack)
			if err != nil {
				reportResult(stack.Version, stack, err)
				return
			}

			reportResult(stack.Version, stack, nil)
		}(ctx, request)
	}

	return nil
}

func (r *Runner) getStackForBatchID(id string) (Stack, error) {
	r.batchToStackMx.Lock()
	res, ok := r.batchToStack[id]
	if ok {
		r.batchToStackMx.Unlock()
		return res.stack, res.err
	}
	_, ok = r.batchToStackCh[id]
	if ok {
		return Stack{}, fmt.Errorf("getStackForBatchID called twice; this is not allowed")
	}
	ch := make(chan stackRes, 1)
	r.batchToStackCh[id] = ch
	r.batchToStackMx.Unlock()

	// 12 minutes is because the stack should have been ready after 10 minutes or returned an error
	// this only exists to ensure that if that code is not blocking that this doesn't block forever
	t := time.NewTimer(12 * time.Minute)
	defer t.Stop()
	select {
	case <-t.C:
		return Stack{}, fmt.Errorf("failed waiting for a response after 12 minutes")
	case res = <-ch:
		return res.stack, res.err
	}
}

func (r *Runner) findInstance(id string) (StateInstance, bool) {
	r.stateMx.Lock()
	defer r.stateMx.Unlock()
	for _, existing := range r.state.Instances {
		if existing.ID == id {
			return existing, true
		}
	}
	return StateInstance{}, false
}

func (r *Runner) addOrUpdateInstance(instance StateInstance) error {
	r.stateMx.Lock()
	defer r.stateMx.Unlock()

	state := r.state
	existed := false
	for idx, existing := range state.Instances {
		if existing.ID == instance.ID {
			state.Instances[idx] = instance
			existed = true
			break
		}
	}
	if !existed {
		state.Instances = append(state.Instances, instance)
	}
	r.state = state
	return r.writeState()
}

func (r *Runner) findStack(id string) (Stack, bool) {
	r.stateMx.Lock()
	defer r.stateMx.Unlock()
	for _, existing := range r.state.Stacks {
		if existing.ID == id {
			return existing, true
		}
	}
	return Stack{}, false
}

func (r *Runner) addOrUpdateStack(stack Stack) error {
	r.stateMx.Lock()
	defer r.stateMx.Unlock()

	state := r.state
	existed := false
	for idx, existing := range state.Stacks {
		if existing.ID == stack.ID {
			state.Stacks[idx] = stack
			existed = true
			break
		}
	}
	if !existed {
		state.Stacks = append(state.Stacks, stack)
	}
	r.state = state
	return r.writeState()
}

func (r *Runner) loadState() error {
	data, err := os.ReadFile(r.getStatePath())
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("failed to read state file %s: %w", r.getStatePath(), err)
	}
	var state State
	err = yaml.Unmarshal(data, &state)
	if err != nil {
		return fmt.Errorf("failed unmarshal state file %s: %w", r.getStatePath(), err)
	}
	r.state = state
	return nil
}

func (r *Runner) writeState() error {
	data, err := yaml.Marshal(&r.state)
	if err != nil {
		return fmt.Errorf("failed to marshal state: %w", err)
	}
	err = os.WriteFile(r.getStatePath(), data, 0644)
	if err != nil {
		return fmt.Errorf("failed to write state file %s: %w", r.getStatePath(), err)
	}
	return nil
}

func (r *Runner) getStatePath() string {
	return filepath.Join(r.cfg.StateDir, "state.yml")
}

func (r *Runner) mergeResults(results map[string]OSRunnerResult) (Result, error) {
	var rawOutput bytes.Buffer
	var jsonOutput bytes.Buffer
	var suites JUnitTestSuites
	for id, res := range results {
		for _, pkg := range res.Packages {
			err := mergePackageResult(pkg, id, false, &rawOutput, &jsonOutput, &suites)
			if err != nil {
				return Result{}, err
			}
		}
		for _, pkg := range res.SudoPackages {
			err := mergePackageResult(pkg, id, true, &rawOutput, &jsonOutput, &suites)
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

func mergePackageResult(pkg OSRunnerPackageResult, batchName string, sudo bool, rawOutput io.Writer, jsonOutput io.Writer, suites *JUnitTestSuites) error {
	suffix := ""
	sudoStr := "false"
	if sudo {
		suffix = "(sudo)"
		sudoStr = "true"
	}
	if pkg.Output != nil {
		rawLogger := &runnerLogger{writer: rawOutput, timestamp: false}
		pkgWriter := newPrefixOutput(rawLogger, fmt.Sprintf("%s(%s)%s: ", pkg.Name, batchName, suffix))
		_, err := pkgWriter.Write(pkg.Output)
		if err != nil {
			return fmt.Errorf("failed to write raw output from %s %s: %w", batchName, pkg.Name, err)
		}
	}
	if pkg.JSONOutput != nil {
		jsonSuffix, err := suffixJSONResults(pkg.JSONOutput, fmt.Sprintf("(%s)%s", batchName, suffix))
		if err != nil {
			return fmt.Errorf("failed to suffix json output from %s %s: %w", batchName, pkg.Name, err)
		}
		_, err = jsonOutput.Write(jsonSuffix)
		if err != nil {
			return fmt.Errorf("failed to write json output from %s %s: %w", batchName, pkg.Name, err)
		}
	}
	if pkg.XMLOutput != nil {
		pkgSuites, err := parseJUnit(pkg.XMLOutput)
		if err != nil {
			return fmt.Errorf("failed to parse junit from %s %s: %w", batchName, pkg.Name, err)
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

func findBatchByID(id string, batches []OSBatch) (OSBatch, bool) {
	for _, batch := range batches {
		if batch.ID == id {
			return batch, true
		}
	}
	return OSBatch{}, false
}

func batchInGroups(batch define.Batch, groups []string) bool {
	for _, g := range groups {
		if batch.Group == g {
			return true
		}
	}
	return false
}

func createBatches(batch define.Batch, platforms []define.OS, groups []string, matrix bool) ([]OSBatch, error) {
	var batches []OSBatch
	if len(groups) > 0 && !batchInGroups(batch, groups) {
		return nil, nil
	}
	specifics, err := getSupported(batch.OS, platforms)
	if errors.Is(err, ErrOSNotSupported) {
		var s SupportedOS
		s.OS.Type = batch.OS.Type
		s.OS.Arch = batch.OS.Arch
		s.OS.Distro = batch.OS.Distro
		if s.OS.Distro == "" {
			s.OS.Distro = "unknown"
		}
		if s.OS.Version == "" {
			s.OS.Version = "unknown"
		}
		b := OSBatch{
			OS:    s,
			Batch: batch,
			Skip:  true,
		}
		b.ID = createBatchID(b)
		batches = append(batches, b)
		return batches, nil
	} else if err != nil {
		return nil, err
	}
	if matrix {
		for _, s := range specifics {
			b := OSBatch{
				OS:    s,
				Batch: batch,
				Skip:  false,
			}
			b.ID = createBatchID(b)
			batches = append(batches, b)
		}
	} else {
		b := OSBatch{
			OS:    specifics[0],
			Batch: batch,
			Skip:  false,
		}
		b.ID = createBatchID(b)
		batches = append(batches, b)
	}
	return batches, nil
}

func filterSingleTest(batches []OSBatch, singleTest string) ([]OSBatch, error) {
	var filtered []OSBatch
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

func filterSingleTestBatch(batch OSBatch, testName string) (OSBatch, bool) {
	for _, pt := range batch.Batch.Tests {
		for _, t := range pt.Tests {
			if t.Name == testName {
				// filter batch to only run one test
				batch.Batch.Tests = []define.BatchPackageTests{
					{
						Name:  pt.Name,
						Tests: []define.BatchPackageTest{t},
					},
				}
				batch.Batch.SudoTests = nil
				// remove stack requirement when the test doesn't need a stack
				if !t.Stack {
					batch.Batch.Stack = nil
				}
				return batch, true
			}
		}
	}
	for _, pt := range batch.Batch.SudoTests {
		for _, t := range pt.Tests {
			if t.Name == testName {
				// filter batch to only run one test
				batch.Batch.SudoTests = []define.BatchPackageTests{
					{
						Name:  pt.Name,
						Tests: []define.BatchPackageTest{t},
					},
				}
				batch.Batch.Tests = nil
				// remove stack requirement when the test doesn't need a stack
				if !t.Stack {
					batch.Batch.Stack = nil
				}
				return batch, true
			}
		}
	}
	return batch, false
}

func filterSupportedOS(batches []OSBatch, provisioner InstanceProvisioner) []OSBatch {
	var filtered []OSBatch
	for _, batch := range batches {
		if ok := provisioner.Supported(batch.OS.OS); ok {
			filtered = append(filtered, batch)
		}
	}
	return filtered
}

// createBatchID creates a consistent/unique ID for the batch
//
// ID needs to be consistent so each execution of the runner always
// selects the same ID for each batch.
func createBatchID(batch OSBatch) string {
	id := batch.OS.Type + "-" + batch.OS.Arch
	if batch.OS.Type == define.Linux {
		id += "-" + batch.OS.Distro
	}
	id += "-" + strings.Replace(batch.OS.Version, ".", "", -1)
	id += "-" + strings.Replace(batch.Batch.Group, ".", "", -1)

	// The batchID needs to be at most 63 characters long otherwise
	// OGC will fail to instantiate the VM.
	maxIDLen := 63
	if len(id) > maxIDLen {
		hash := fmt.Sprintf("%x", md5.Sum([]byte(id)))
		hashLen := utf8.RuneCountInString(hash)
		id = id[:maxIDLen-hashLen-1] + "-" + hash
	}

	return strings.ToLower(id)
}

type runnerLogger struct {
	writer    io.Writer
	timestamp bool
}

func (l *runnerLogger) Logf(format string, args ...any) {
	if l.timestamp {
		_, _ = fmt.Fprintf(l.writer, "[%s] >>> %s\n", time.Now().Format(time.StampMilli), fmt.Sprintf(format, args...))
	} else {
		_, _ = fmt.Fprintf(l.writer, ">>> %s\n", fmt.Sprintf(format, args...))
	}
}

type batchLogger struct {
	wrapped Logger
	prefix  string
}

func (b *batchLogger) Logf(format string, args ...any) {
	b.wrapped.Logf("(%s) %s", b.prefix, fmt.Sprintf(format, args...))
}

type stackRes struct {
	stack Stack
	err   error
}

type stackReq struct {
	request StackRequest
	stack   *Stack
}
