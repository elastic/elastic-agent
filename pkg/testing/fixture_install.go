// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package testing

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/pkg/control/v2/client"
	"github.com/elastic/elastic-agent/pkg/core/process"
)

// ErrNotInstalled is returned in cases where Agent isn't installed
var ErrNotInstalled = errors.New("Elastic Agent is not installed") //nolint:stylecheck // Elastic Agent is a proper noun

// CmdOpts creates vectors of command arguments for different agent commands
type CmdOpts interface {
	toCmdArgs() []string
}

// EnrollOpts specifies the options for the enroll command
type EnrollOpts struct {
	URL             string // --url
	EnrollmentToken string // --enrollment-token
}

func (e EnrollOpts) toCmdArgs() []string {
	var args []string
	if e.URL != "" {
		args = append(args, "--url", e.URL)
	}
	if e.EnrollmentToken != "" {
		args = append(args, "--enrollment-token", e.EnrollmentToken)
	}
	return args
}

// InstallOpts specifies the options for the install command
type InstallOpts struct {
	BasePath       string // --base-path
	Force          bool   // --force
	Insecure       bool   // --insecure
	NonInteractive bool   // --non-interactive
	ProxyURL       string // --proxy-url

	EnrollOpts
}

func (i InstallOpts) toCmdArgs() []string {
	var args []string
	if i.BasePath != "" {
		args = append(args, "--base-path", i.BasePath)
	}
	if i.Force {
		args = append(args, "--force")
	}
	if i.Insecure {
		args = append(args, "--insecure")
	}
	if i.NonInteractive {
		args = append(args, "--non-interactive")
	}
	if i.ProxyURL != "" {
		args = append(args, "--proxy-url="+i.ProxyURL)
	}

	args = append(args, i.EnrollOpts.toCmdArgs()...)

	return args
}

// Install installs the prepared Elastic Agent binary and returns:
//   - the combined output of stdout and stderr
//   - an error if any.
func (f *Fixture) Install(ctx context.Context, installOpts *InstallOpts, opts ...process.CmdOption) ([]byte, error) {
	installArgs := []string{"install"}
	if installOpts != nil {
		installArgs = append(installArgs, installOpts.toCmdArgs()...)
	}
	out, err := f.Exec(ctx, installArgs, opts...)
	if err != nil {
		return out, fmt.Errorf("error running agent install command: %w", err)
	}

	f.installed = true
	f.installOpts = installOpts

	if installOpts.BasePath == "" {
		f.workDir = filepath.Join(paths.DefaultBasePath, "Elastic", "Agent")
	} else {
		f.workDir = filepath.Join(installOpts.BasePath, "Elastic", "Agent")
	}

	// we just installed agent, the control socket is at a well-known location
	c := client.New(client.WithAddress(paths.ControlSocketPath))
	f.setClient(c)

	f.t.Cleanup(func() {
		if !f.installed {
			// not installed; no need to clean up or collect diagnostics
			return
		}

		// diagnostics is collected when either the environment variable
		// AGENT_KEEP_INSTALLED=true or the test is marked failed
		collect := collectDiag()
		failed := f.t.Failed()
		if collect || failed {
			if collect {
				f.t.Logf("collecting diagnostics; AGENT_COLLECT_DIAG=true")
			} else if failed {
				f.t.Logf("collecting diagnostics; test failed")
			}
			f.collectDiagnostics()
		}

		// environment variable AGENT_KEEP_INSTALLED=true will skip the uninstall
		// useful to debug the issue with the Elastic Agent
		if keepInstalled() {
			f.t.Logf("skipping uninstall; AGENT_KEEP_INSTALLED=true")
		} else {
			out, err := f.Uninstall(ctx, &UninstallOpts{Force: true})
			f.setClient(nil)
			if err != nil &&
				(errors.Is(err, ErrNotInstalled) ||
					strings.Contains(
						err.Error(),
						"elastic-agent: no such file or directory")) {
				// Agent fixture has already been uninstalled, perhaps by
				// an explicit call to fixture.Uninstall, so nothing needs
				// to be done here.
				return
			}
			require.NoErrorf(f.t, err, "uninstalling agent failed. Output: %q", out)
		}
<<<<<<< HEAD
=======

		// 5 minute timeout, to ensure that it at least doesn't get stuck.
		// original context is not used as it could have a timeout on the context
		// for the install and we don't want that context to prevent the uninstall
		uninstallCtx, uninstallCancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer uninstallCancel()
		out, err := f.Uninstall(uninstallCtx, &UninstallOpts{Force: true, UninstallToken: f.uninstallToken})
		f.setClient(nil)
		if err != nil &&
			(errors.Is(err, ErrNotInstalled) ||
				strings.Contains(
					err.Error(),
					"elastic-agent: no such file or directory")) {
			f.t.Logf("fixture.Install Cleanup: agent was already uninstalled, skipping uninstall")
			// Agent fixture has already been uninstalled, perhaps by
			// an explicit call to fixture.Uninstall, so nothing needs
			// to be done here.
			return
		}
		require.NoErrorf(f.t, err, "uninstalling agent failed. Output: %q", out)
>>>>>>> 35dbbdea9b (Add Windows support to integration testing runner (#2941))
	})

	return out, nil
}

type UninstallOpts struct {
	Force bool // --force
}

func (i UninstallOpts) toCmdArgs() []string {
	var args []string
	if i.Force {
		args = append(args, "--force")
	}

	return args
}

// Uninstall uninstalls the installed Elastic Agent binary
func (f *Fixture) Uninstall(ctx context.Context, uninstallOpts *UninstallOpts, opts ...process.CmdOption) ([]byte, error) {
	if !f.installed {
		return nil, ErrNotInstalled
	}

	uninstallArgs := []string{"uninstall"}
	if uninstallOpts != nil {
		uninstallArgs = append(uninstallArgs, uninstallOpts.toCmdArgs()...)
	}
	out, err := f.Exec(ctx, uninstallArgs, opts...)
	if err != nil {
		return out, fmt.Errorf("error running uninstall command: %w", err)
	}
	f.installed = false

	// Check that Elastic Agent files are actually removed
	basePath := f.installOpts.BasePath
	if basePath == "" {
		basePath = paths.DefaultBasePath
	}
	topPath := filepath.Join(basePath, "Elastic", "Agent")
	topPathStats, err := os.Stat(topPath)
	if errors.Is(err, fs.ErrNotExist) {
		// the path does not exist anymore, all good!
		return out, nil
	}

	if err != nil {
		return out, fmt.Errorf("error stating agent path: %w", err)
	}

	if err != nil && topPathStats != nil {
		return out, fmt.Errorf("Elastic Agent is still installed at [%s]", topPath) //nolint:stylecheck // Elastic Agent is a proper noun
	}

	return out, nil
}

func (f *Fixture) collectDiagnostics() {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancel()

	dir, err := findProjectRoot(f.caller)
	if err != nil {
		f.t.Logf("failed to collect diagnostics; failed to find project root: %s", err)
		return
	}
	diagPath := filepath.Join(dir, "build", "diagnostics")
	err = os.MkdirAll(diagPath, 0755)
	if err != nil {
		f.t.Logf("failed to collect diagnostics; failed to create %s: %s", diagPath, err)
		return
	}
<<<<<<< HEAD
	outputPath := filepath.Join(diagPath, fmt.Sprintf("%s-diagnostics-%s.zip", f.t.Name(), time.Now().Format(time.RFC3339)))
=======

	stamp := time.Now().Format(time.RFC3339)
	if runtime.GOOS == "windows" {
		// on Windows a filename cannot contain a ':' as this collides with disk labels (aka. C:\)
		stamp = strings.ReplaceAll(stamp, ":", "-")
	}

	// Sub-test names are separated by "/" characters which are not valid filenames on Linux.
	sanitizedTestName := strings.ReplaceAll(f.t.Name(), "/", "-")
	outputPath := filepath.Join(diagPath, fmt.Sprintf("%s-diagnostics-%s.zip", sanitizedTestName, stamp))
>>>>>>> 35dbbdea9b (Add Windows support to integration testing runner (#2941))

	output, err := f.Exec(ctx, []string{"diagnostics", "-f", outputPath})
	if err != nil {
		f.t.Logf("failed to collect diagnostics to %s (%s): %s", outputPath, err, output)
<<<<<<< HEAD
=======

		// possible that the test was so fast that the Elastic Agent was just installed, the control protocol is
		// not fully running yet. wait 15 seconds to try again, ensuring that best effort is performed in fetching
		// diagnostics
		if strings.Contains(string(output), "connection error") {
			f.t.Logf("retrying in 15 seconds due to connection error; possible Elastic Agent was not fully started")
			time.Sleep(15 * time.Second)
			output, err = f.Exec(ctx, []string{"diagnostics", "-f", outputPath})
			f.t.Logf("failed to collect diagnostics a second time at %s (%s): %s", outputPath, err, output)
		}
		if err != nil {
			// If collecting diagnostics fails, zip up the entire installation directory with the hope that it will contain logs.
			f.t.Logf("creating zip archive of the installation directory: %s", f.workDir)
			zipPath := filepath.Join(diagPath, fmt.Sprintf("%s-install-directory-%s.zip", sanitizedTestName, time.Now().Format(time.RFC3339)))
			err = f.archiveInstallDirectory(f.workDir, zipPath)
			if err != nil {
				f.t.Logf("failed to zip install directory to %s: %s", zipPath, err)
			}
		}
>>>>>>> 35dbbdea9b (Add Windows support to integration testing runner (#2941))
	}
}

func collectDiag() bool {
	// failure reports false (ignore error)
	v, _ := strconv.ParseBool(os.Getenv("AGENT_COLLECT_DIAG"))
	return v
}

func keepInstalled() bool {
	// failure reports false (ignore error)
	v, _ := strconv.ParseBool(os.Getenv("AGENT_KEEP_INSTALLED"))
	return v
}
