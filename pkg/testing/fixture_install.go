// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package testing

import (
	"archive/zip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	gotesting "testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-libs/mapstr"
	agentsystemprocess "github.com/elastic/elastic-agent-system-metrics/metric/system/process"
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
	DelayEnroll    bool   // --delay-enroll

	Privileged bool // inverse of --unprivileged (as false is the default)

	EnrollOpts
}

func (i InstallOpts) toCmdArgs(operatingSystem string) ([]string, error) {
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
	if i.DelayEnroll {
		args = append(args, "--delay-enroll")
	}
	if !i.Privileged {
		args = append(args, "--unprivileged")
	}

	args = append(args, i.EnrollOpts.toCmdArgs()...)

	return args, nil
}

// Install installs the prepared Elastic Agent binary and registers a t.Cleanup
// function to uninstall the agent if it hasn't been uninstalled. It also takes
// care of collecting a diagnostics when AGENT_COLLECT_DIAG=true or the test
// has failed.
// It returns:
//   - the combined output of Install command stdout and stderr
//   - an error if any.
func (f *Fixture) Install(ctx context.Context, installOpts *InstallOpts, opts ...process.CmdOption) ([]byte, error) {
	f.t.Logf("[test %s] Inside fixture install function", f.t.Name())

	// check for running agents before installing, but proceed anyway
	assert.Empty(f.t, getElasticAgentProcesses(f.t), "there should be no running agent at beginning of Install()")

	installArgs := []string{"install"}
	if installOpts == nil {
		// default options when not provided
		installOpts = &InstallOpts{}
	}
	installOptsArgs, err := installOpts.toCmdArgs(f.operatingSystem)
	if err != nil {
		return nil, err
	}
	installArgs = append(installArgs, installOptsArgs...)
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
	socketPath := fmt.Sprintf("unix://%s", paths.ControlSocketRunSymlink) // use symlink as that works for all versions
	if runtime.GOOS == "windows" {
		// Windows uses a fixed named pipe, that is always the same.
		// It is the same even running in unprivileged mode.
		socketPath = paths.WindowsControlSocketInstalledPath
	} else if !installOpts.Privileged {
		// Unprivileged versions move the socket to inside the installed directory
		// of the Elastic Agent.
		socketPath = paths.ControlSocketFromPath(runtime.GOOS, f.workDir)
	}
	c := client.New(client.WithAddress(socketPath))
	f.setClient(c)

	f.t.Cleanup(func() {
		if f.t.Failed() {
			procs := getProcesses(f.t, `.*`)
			dir, err := findProjectRoot(f.caller)
			if err != nil {
				f.t.Logf("failed to dump process; failed to find project root: %s", err)
				return
			}

			// Sub-test names are separated by "/" characters which are not valid filenames on Linux.
			sanitizedTestName := strings.ReplaceAll(f.t.Name(), "/", "-")

			filePath := filepath.Join(dir, "build", "diagnostics", fmt.Sprintf("TEST-%s-%s-%s-ProcessDump.json", sanitizedTestName, f.operatingSystem, f.architecture))
			f.t.Logf("Dumping running processes in %s", filePath)
			file, err := os.OpenFile(filePath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
			if err != nil {
				f.t.Logf("failed to dump process; failed to create output file %s root: %s", file.Name(), err)
				return
			}
			defer func(file *os.File) {
				err := file.Close()
				if err != nil {
					f.t.Logf("error closing file %s: %s", file.Name(), err)
				}
			}(file)
			err = json.NewEncoder(file).Encode(procs)
			if err != nil {
				f.t.Logf("error serializing processes: %s", err)
			}
		}
	})

	f.t.Cleanup(func() {
		// check for running agents after uninstall had a chance to run
		assert.Empty(f.t, getElasticAgentProcesses(f.t), "there should be no running agent at the end of the test")
	})

	f.t.Cleanup(func() {
		f.t.Logf("[test %s] Inside fixture cleanup function", f.t.Name())

		if !f.installed {
			f.t.Logf("skipping uninstall; agent not installed (fixture.installed is false)")
			// not installed; no need to clean up or collect diagnostics
			return
		}

		// diagnostics is collected when either the environment variable
		// AGENT_COLLECT_DIAG=true or the test is marked failed
		collect := collectDiagFlag()
		failed := f.t.Failed()
		if collect || failed {
			if collect {
				f.t.Logf("collecting diagnostics; AGENT_COLLECT_DIAG=true")
			} else if failed {
				f.t.Logf("collecting diagnostics; test failed")
			}
			f.collectDiagnostics()
		}

		// environment variable AGENT_KEEP_INSTALLED=true will skip the uninstallation
		// useful to debug the issue with the Elastic Agent
		if f.t.Failed() && keepInstalledFlag() {
			f.t.Logf("skipping uninstall; test failed and AGENT_KEEP_INSTALLED=true")
			return
		}

		if keepInstalledFlag() {
			f.t.Logf("ignoring AGENT_KEEP_INSTALLED=true as test succeeded, " +
				"keeping the agent installed will jeopardise other tests")
		}

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
	})

	return out, nil
}

type runningProcess struct {
	// Basic Process data
	Name     string                      `json:"name,omitempty"`
	State    agentsystemprocess.PidState `json:"state,omitempty"`
	Username string                      `json:"username,omitempty"`
	Pid      int                         `json:"pid"`
	Ppid     int                         `json:"ppid"`
	Pgid     int                         `json:"pgid"`

	// Extended Process Data
	Args    []string `json:"args,omitempty"`
	Cmdline string   `json:"cmdline,omitempty"`
	Cwd     string   `json:"cwd,omitempty"`
	Exe     string   `json:"exe,omitempty"`
	Env     mapstr.M `json:"env,omitempty"`
}

func (p runningProcess) String() string {
	return fmt.Sprintf("{PID:%v, PPID: %v, Cwd: %s, Exe: %s, Cmdline: %s, Args: %v}",
		p.Pid, p.Ppid, p.Cwd, p.Exe, p.Cmdline, p.Args)
}

func mapProcess(p agentsystemprocess.ProcState) runningProcess {
	mappedProcess := runningProcess{
		Name:     p.Name,
		State:    p.State,
		Username: p.Username,
		// map pid/gid to int and default to an obvious impossible pid if we don't have a value
		Pid:     p.Pid.ValueOr(-1),
		Ppid:    p.Ppid.ValueOr(-1),
		Pgid:    p.Pgid.ValueOr(-1),
		Cmdline: p.Cmdline,
		Cwd:     p.Cwd,
		Exe:     p.Exe,
		Args:    make([]string, len(p.Args)),
		Env:     make(mapstr.M),
	}
	copy(mappedProcess.Args, p.Args)
	for k, v := range p.Env {
		mappedProcess.Env[k] = v
	}
	return mappedProcess
}

func getElasticAgentProcesses(t *gotesting.T) []runningProcess {
	return getProcesses(t, `.*elastic\-agent.*`)
}

func getProcesses(t *gotesting.T, regex string) []runningProcess {
	procStats := agentsystemprocess.Stats{
		Procs: []string{regex},
	}

	err := procStats.Init()
	if !assert.NoError(t, err, "error initializing process.Stats") {
		// we failed
		return nil
	}

	_, pids, err := procStats.FetchPids()
	if !assert.NoError(t, err, "error fetching process information") {
		// we failed a bit further
		return nil
	}

	processes := make([]runningProcess, 0, len(pids))

	for _, p := range pids {
		processes = append(processes, mapProcess(p))
	}

	return processes
}

type UninstallOpts struct {
	Force          bool // --force
	UninstallToken string
}

func (i UninstallOpts) toCmdArgs() []string {
	var args []string
	if i.Force {
		args = append(args, "--force")
	}

	if i.UninstallToken != "" {
		args = append(args, "--uninstall-token", i.UninstallToken)
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

	stamp := time.Now().Format(time.RFC3339)
	if runtime.GOOS == "windows" {
		// on Windows a filename cannot contain a ':' as this collides with disk labels (aka. C:\)
		stamp = strings.ReplaceAll(stamp, ":", "-")
	}

	// Sub-test names are separated by "/" characters which are not valid filenames on Linux.
	sanitizedTestName := strings.ReplaceAll(f.t.Name(), "/", "-")
	outputPath := filepath.Join(diagPath, fmt.Sprintf("%s-diagnostics-%s.zip", sanitizedTestName, stamp))

	output, err := f.Exec(ctx, []string{"diagnostics", "-f", outputPath})
	if err != nil {
		f.t.Logf("failed to collect diagnostics to %s (%s): %s", outputPath, err, output)

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
			timestamp := strings.ReplaceAll(time.Now().Format(time.RFC3339), ":", "-")
			zipPath := filepath.Join(diagPath, fmt.Sprintf("%s-install-directory-%s.zip", sanitizedTestName, timestamp))
			err = f.archiveInstallDirectory(f.workDir, zipPath)
			if err != nil {
				f.t.Logf("failed to zip install directory to %s: %s", zipPath, err)
			}
		}
	}
}

func (f *Fixture) archiveInstallDirectory(installPath string, outputPath string) error {
	file, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("creating zip output file %s: %w", outputPath, err)
	}
	defer file.Close()

	w := zip.NewWriter(file)
	defer w.Close()

	walker := func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		file, err := os.Open(path)
		if err != nil {
			f.t.Logf("failed to add %s to zip, continuing: %s", path, err)
			return nil
		}
		defer file.Close()

		f, err := w.Create(path)
		if err != nil {
			return err
		}

		_, err = io.Copy(f, file)
		if err != nil {
			return err
		}

		return nil
	}

	err = filepath.Walk(f.workDir, walker)
	if err != nil {
		return fmt.Errorf("walking %s to create zip: %w", f.workDir, err)
	}

	return nil
}

func collectDiagFlag() bool {
	// failure reports false (ignore error)
	v, _ := strconv.ParseBool(os.Getenv("AGENT_COLLECT_DIAG"))
	return v
}

func keepInstalledFlag() bool {
	// failure reports false (ignore error)
	v, _ := strconv.ParseBool(os.Getenv("AGENT_KEEP_INSTALLED"))
	return v
}
