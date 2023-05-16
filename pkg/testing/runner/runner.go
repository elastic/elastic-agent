package runner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"k8s.io/utils/strings/slices"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/rs/xid"
	"golang.org/x/crypto/ssh"
	"golang.org/x/sync/errgroup"
	"gopkg.in/yaml.v2"

	"github.com/elastic/elastic-agent/pkg/core/process"
	"github.com/elastic/elastic-agent/pkg/testing/define"
)

// Runner runs the tests on remote instances.
type Runner struct {
	cfg     Config
	batches []LayoutBatch
}

// NewRunner creates a new runner based on the provided batches.
func NewRunner(cfg Config, batches ...define.Batch) (*Runner, error) {
	err := cfg.Validate()
	if err != nil {
		return nil, err
	}
	var layoutBatches []LayoutBatch
	for _, b := range batches {
		lb, err := createBatch(b)
		if err != nil {
			return nil, err
		}
		layoutBatches = append(layoutBatches, lb)
	}
	return &Runner{
		cfg:     cfg,
		batches: layoutBatches,
	}, nil
}

// Run runs all the tests.
func (r *Runner) Run(ctx context.Context) error {
	// validate tests can even be performed
	err := r.validate()
	if err != nil {
		return err
	}

	// prepare
	prepareCtx, prepareCancel := context.WithTimeout(ctx, 10*time.Minute)
	defer prepareCancel()
	sshAuth, repoArchive, err := r.prepare(prepareCtx)
	if err != nil {
		return err
	}

	// import the calculated layouts
	importCtx, importCancel := context.WithTimeout(ctx, 30*time.Second)
	defer importCancel()
	err = r.ogcImport(importCtx)
	if err != nil {
		return err
	}

	// bring up all the instances
	upCtx, upCancel := context.WithTimeout(ctx, 30*time.Minute)
	defer upCancel()
	err = r.ogcUp(upCtx)
	if err != nil {
		return err
	}
	defer func() {
		// always clean
		_ = r.Clean(ctx)
	}()

	// fetch the machines and run the batches on the machine
	machines, err := r.ogcMachines(ctx)
	if err != nil {
		return err
	}
	return r.runMachines(ctx, sshAuth, repoArchive, machines)
}

// Clean performs a cleanup to ensure anything that could have been left running is removed.
func (r *Runner) Clean(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	return r.ogcDown(ctx)
}

// runMachines runs the batch on each machine in parallel.
func (r *Runner) runMachines(ctx context.Context, sshAuth ssh.AuthMethod, repoArchive string, machines []OGCMachine) error {
	g, ctx := errgroup.WithContext(ctx)
	for _, m := range machines {
		func(m OGCMachine) {
			g.Go(func() error {
				batch, ok := findLayoutBatchByID(m.Layout.Name, r.batches)
				if !ok {
					return fmt.Errorf("unable to find layout batch with ID: %s", m.Layout.Name)
				}
				err := r.runMachine(ctx, sshAuth, repoArchive, batch, m)
				if err != nil {
					fmt.Printf(">>> Failed for instance %s @ %s (holding for 10 minutes to debug)\n", m.InstanceID, m.PublicIP)
					<-time.After(10 * time.Minute)
					return err
				}
				return nil
			})
		}(m)
	}
	return g.Wait()
}

// runMachine runs the batch on the machine.
func (r *Runner) runMachine(ctx context.Context, sshAuth ssh.AuthMethod, repoArchive string, batch LayoutBatch, machine OGCMachine) error {
	fmt.Printf(">>> Trying to create SSH connection to instance %s @ %s\n", machine.InstanceID, machine.PublicIP)
	connectCtx, connectCancel := context.WithTimeout(ctx, 10*time.Minute)
	defer connectCancel()
	client, err := sshConnect(connectCtx, machine.PublicIP, machine.Layout.Username, sshAuth)
	if err != nil {
		fmt.Printf(">>> Failed to connect to instance %s @ %s: %s\n", machine.InstanceID, machine.PublicIP, err)
		return fmt.Errorf("failed to connect to instance %s: %w", machine.InstanceID, err)
	}
	defer client.Close()
	fmt.Printf(">>> Connected over SSH to instance %s\n", machine.InstanceID)

	// run the tests on the host
	fmt.Printf(">>> Preparing instance %s\n", machine.InstanceID)
	err = batch.LayoutOS.Runner.Prepare(ctx, client, machine.InstanceID, batch.LayoutOS.OS.Arch, r.cfg.GOVersion, repoArchive, r.getBuildPath(batch))
	if err != nil {
		fmt.Printf(">>> Failed to prepare instance %s: %s\n", machine.InstanceID, err)
		return fmt.Errorf("failed to prepare instance %s: %w", machine.InstanceID, err)
	}

	return nil
}

// validate ensures that required builds of Elastic Agent exist
func (r *Runner) validate() error {
	var requiredFiles []string
	for _, b := range r.batches {
		if !b.Skip {
			buildName := r.getBuildPath(b)
			if !slices.Contains(requiredFiles, buildName) {
				requiredFiles = append(requiredFiles, buildName)
			}
		}
	}
	var missingFiles []string
	for _, file := range requiredFiles {
		fullPath := filepath.Join(r.cfg.BuildDir, file)
		_, err := os.Stat(fullPath)
		if os.IsNotExist(err) {
			missingFiles = append(missingFiles, fullPath)
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
	return fmt.Sprintf("elastic-agent-%s-%s-%s.%s", r.cfg.AgentVersion, b.LayoutOS.OS.Type, arch, ext)
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
	fmt.Printf(">>> Creating zip archive of repo to send to remove hosts\n")
	err := createRepoZipArchive(ctx, repoDir, zipPath)
	if err != nil {
		return "", err
	}
	return zipPath, nil
}

// ogcPull pulls the latest ogc version.
func (r *Runner) ogcPull(ctx context.Context) error {
	args := []string{
		"pull",
		"docker.io/gorambo/ogc:gh-19",
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
func (r *Runner) ogcUp(ctx context.Context) error {
	fmt.Printf(">>> Bring up instances through ogc\n")
	proc, err := r.ogcRun(ctx, []string{"up", LayoutIntegrationTag}, false)
	if err != nil {
		return fmt.Errorf("failed to run ogc up: %w", err)
	}
	ps := <-proc.Wait()
	if ps.ExitCode() != 0 {
		return fmt.Errorf("failed to run ogc up: docker run exited with code: %d", ps.ExitCode())
	}
	return nil
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

// ogcMachines brings up all the instances.
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
		"ogc:local-latest",
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

func attachOutErr(c *exec.Cmd) error {
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	return nil
}

func attachOut(w io.Writer) process.CmdOption {
	return func(c *exec.Cmd) error {
		c.Stdout = w
		c.Stderr = os.Stderr
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

func createBatch(batch define.Batch) (LayoutBatch, error) {
	skip := false
	specific, err := getSupported(batch.OS)
	if errors.Is(err, ErrOSNotSupported) {
		skip = true
		specific.OS.Type = batch.OS.Type
		specific.OS.Arch = batch.OS.Arch
		specific.OS.Distro = batch.OS.Distro
		if specific.OS.Distro == "" {
			specific.OS.Distro = "unknown"
		}
		if specific.OS.Version == "" {
			specific.OS.Version = "unknown"
		}
	} else if err != nil {
		return LayoutBatch{}, err
	}
	return LayoutBatch{
		ID:       xid.New().String(),
		LayoutOS: specific,
		Batch:    batch,
		Skip:     skip,
	}, nil
}
