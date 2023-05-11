package runner

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v2"

	"github.com/elastic/elastic-agent/pkg/core/process"
	"github.com/elastic/elastic-agent/pkg/testing/define"
)

// Runner runs the tests on remote instances.
type Runner struct {
	batches []LayoutBatch
}

// NewRunner creates a new runner based on the provided batches.
func NewRunner(batches ...define.Batch) (*Runner, error) {
	var layoutBatches []LayoutBatch
	for _, b := range batches {
		lb, err := createBatch(b)
		if err != nil {
			return nil, err
		}
		layoutBatches = append(layoutBatches, lb)
	}
	return &Runner{
		batches: layoutBatches,
	}, nil
}

// Run runs all the tests.
func (r *Runner) Run(ctx context.Context) error {
	// prepare OGC
	prepareCtx, prepareCancel := context.WithTimeout(ctx, 10*time.Minute)
	defer prepareCancel()
	err := r.ogcPrepare(prepareCtx)
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
	return r.ogcUp(upCtx)
}

// ogcPrepare prepares for OGC to be ran.
//
// Creates the SSH keys to use and pulls the latest container for OGC.
func (r *Runner) ogcPrepare(ctx context.Context) error {
	wd, err := r.getWorkDir()
	if err != nil {
		return err
	}
	cacheDir := filepath.Join(wd, ".ogc-cache")
	_, err = os.Stat(cacheDir)
	if errors.Is(err, os.ErrNotExist) {
		err = os.Mkdir(cacheDir, 0755)
		if err != nil {
			return fmt.Errorf("failed to create %q: %w", cacheDir, err)
		}
	} else if err != nil {
		// unknown error
		return err
	}
	privateKey := filepath.Join(cacheDir, "id_rsa")
	_, priErr := os.Stat(privateKey)
	publicKey := filepath.Join(cacheDir, "id_rsa.pub")
	_, pubErr := os.Stat(publicKey)
	if errors.Is(priErr, os.ErrNotExist) || errors.Is(pubErr, os.ErrNotExist) {
		// either is missing (re-create)
		_ = os.Remove(privateKey)
		_ = os.Remove(publicKey)
		pri, err := newSSHPrivateKey()
		if err != nil {
			return fmt.Errorf("failed to create ssh private key: %w", err)
		}
		pubBytes, err := newSSHPublicKey(&pri.PublicKey)
		if err != nil {
			return fmt.Errorf("failed to create ssh public key: %w", err)
		}
		priBytes := sshEncodeToPEM(pri)
		err = os.WriteFile(privateKey, priBytes, 0644)
		if err != nil {
			return fmt.Errorf("failed to write ssh private key: %w", err)
		}
		err = os.WriteFile(publicKey, pubBytes, 0644)
		if err != nil {
			return fmt.Errorf("failed to write ssh public key: %w", err)
		}
	} else if priErr != nil {
		// unknown error
		return priErr
	} else if pubErr != nil {
		// unknown error
		return pubErr
	}
	return r.ogcPull(ctx)
}

// ogcPull pulls the latest ogc version.
func (r *Runner) ogcPull(ctx context.Context) error {
	args := []string{
		"pull",
		"docker.io/gorambo/ogc:gh-19",
	}
	proc, err := process.Start("docker", process.WithContext(ctx), process.WithArgs(args), process.WithCmdOptions(attachOutErr))
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
func (r *Runner) ogcImport(ctx context.Context) (err error) {
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
	proc, err := r.ogcRun(ctx, []string{"layout", "import"}, true)
	if err != nil {
		return fmt.Errorf("failed to run ogc import: %w", err)
	}
	_, err = proc.Stdin.Write(layoutData)
	if err != nil {
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
func (r *Runner) ogcUp(ctx context.Context) (err error) {
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

func (r *Runner) ogcRun(ctx context.Context, args []string, interactive bool) (*process.Info, error) {
	wd, err := r.getWorkDir()
	if err != nil {
		return nil, err
	}
	runArgs := []string{"run"}
	if interactive {
		runArgs = append(runArgs, "-i")
	}
	runArgs = append(runArgs,
		"--rm",
		"-v",
		fmt.Sprintf("%s:%s", wd, wd),
		"-w",
		wd,
		"docker.io/gorambo/ogc:gh-19",
		"--",
		"ogc",
		"-v",
	)
	runArgs = append(runArgs, args...)
	fmt.Printf("args: %+v\n", runArgs)
	return process.Start("docker", process.WithContext(ctx), process.WithArgs(runArgs), process.WithCmdOptions(attachOutErr))
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
	id := fmt.Sprintf("%s/%s/%s/%s", specific.OS.Type, specific.OS.Arch, specific.OS.Distro, specific.OS.Version)
	if batch.Isolate {
		var test define.BatchPackageTests
		if len(batch.SudoTests) > 0 {
			test = batch.SudoTests[0]
		} else if len(batch.Tests) > 0 {
			test = batch.Tests[0]
		}
		id = fmt.Sprintf("%s-%s-%s", id, path.Base(test.Name), test.Tests[0])
	}
	return LayoutBatch{
		ID:       id,
		LayoutOS: specific,
		Batch:    batch,
		Skip:     skip,
	}, nil
}
