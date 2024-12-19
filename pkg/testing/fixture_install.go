// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package testing

import (
	"archive/zip"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
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

	// SSL/TLS options
	CertificateAuthorities []string // --certificate-authorities
	Certificate            string   // --elastic-agent-cert
	Key                    string   // --elastic-agent-cert-key
	KeyPassphrasePath      string   // --elastic-agent-cert-key-passphrase
}

func (e EnrollOpts) toCmdArgs() []string {
	var args []string
	if e.URL != "" {
		args = append(args, "--url", e.URL)
	}
	if e.EnrollmentToken != "" {
		args = append(args, "--enrollment-token", e.EnrollmentToken)
	}

	if len(e.CertificateAuthorities) > 0 {
		args = append(args, "--certificate-authorities="+strings.Join(e.CertificateAuthorities, ","))
	}

	if e.Certificate != "" {
		args = append(args, "--elastic-agent-cert="+e.Certificate)
	}
	if e.Key != "" {
		args = append(args, "--elastic-agent-cert-key="+e.Key)
	}
	if e.KeyPassphrasePath != "" {
		args = append(args, "--elastic-agent-cert-key-passphrase="+e.KeyPassphrasePath)
	}

	return args
}

type FleetBootstrapOpts struct {
	ESHost       string // --fleet-server-es
	ServiceToken string // --fleet-server-service-token
	Policy       string // --fleet-server-policy
	Port         int    // --fleet-server-port
}

func (f FleetBootstrapOpts) toCmdArgs() []string {
	var args []string
	if f.ESHost != "" {
		args = append(args, "--fleet-server-es", f.ESHost)
	}
	if f.ServiceToken != "" {
		args = append(args, "--fleet-server-service-token", f.ServiceToken)
	}
	if f.Policy != "" {
		args = append(args, "--fleet-server-policy", f.Policy)
	}
	if f.Port > 0 {
		args = append(args, "--fleet-server-port", fmt.Sprintf("%d", f.Port))
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
	Develop        bool   // --develop, not supported for DEB and RPM. Calling Install() sets Namespace to the development namespace so that checking only for a Namespace is sufficient.
	Namespace      string // --namespace, not supported for DEB and RPM.

	Privileged bool // inverse of --unprivileged (as false is the default)
	Username   string
	Group      string

	EnrollOpts
	FleetBootstrapOpts
}

func (i *InstallOpts) ToCmdArgs() []string {
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
	if i.Namespace != "" {
		args = append(args, "--namespace="+i.Namespace)
	}
	if i.Develop {
		args = append(args, "--develop")
		if i.Namespace == "" {
			// If --namespace was used it will override the development namespace.
			i.Namespace = paths.DevelopmentNamespace
		}
	}

	if i.Username != "" {
		args = append(args, "--user", i.Username)
	}

	if i.Group != "" {
		args = append(args, "--group", i.Group)
	}

	args = append(args, i.EnrollOpts.toCmdArgs()...)
	args = append(args, i.FleetBootstrapOpts.toCmdArgs()...)

	return args
}

// Install installs the prepared Elastic Agent binary and registers a t.Cleanup
// function to uninstall the agent if it hasn't been uninstalled. It also takes
// care of collecting a diagnostics when AGENT_COLLECT_DIAG=true or the test
// has failed.
// It returns:
//   - the combined output of Install command stdout and stderr
//   - an error if any.
func (f *Fixture) Install(ctx context.Context, installOpts *InstallOpts, opts ...process.CmdOption) ([]byte, error) {
	return f.installFunc(ctx, installOpts, true, opts...)
}

func (f *Fixture) InstallWithoutEnroll(ctx context.Context, installOpts *InstallOpts, opts ...process.CmdOption) ([]byte, error) {
	return f.installFunc(ctx, installOpts, false, opts...)
}

func (f *Fixture) installFunc(ctx context.Context, installOpts *InstallOpts, shouldEnroll bool, opts ...process.CmdOption) ([]byte, error) {
	f.t.Logf("[test %s] Inside fixture install function", f.t.Name())

	// check for running agents before installing, but only if not installed into a namespace whose point is allowing two agents at once.
	if installOpts != nil && !installOpts.Develop && installOpts.Namespace == "" {
		assert.Empty(f.t, getElasticAgentProcesses(f.t), "there should be no running agent at beginning of Install()")
	}

	switch f.packageFormat {
	case "targz", "zip":
		return f.installNoPkgManager(ctx, installOpts, shouldEnroll, opts)
	case "deb":
		return f.installDeb(ctx, installOpts, shouldEnroll, opts)
	case "rpm":
		return f.installRpm(ctx, installOpts, shouldEnroll, opts)
	default:
		return nil, fmt.Errorf("package format %s isn't supported yet", f.packageFormat)
	}
}

// installNoPkgManager installs the prepared Elastic Agent binary from
// the tgz or zip archive and registers a t.Cleanup function to
// uninstall the agent if it hasn't been uninstalled. It also takes
// care of collecting a diagnostics when AGENT_COLLECT_DIAG=true or
// the test has failed.
// It returns:
//   - the combined output of Install command stdout and stderr
//   - an error if any.
func (f *Fixture) installNoPkgManager(ctx context.Context, installOpts *InstallOpts, shouldEnroll bool, opts []process.CmdOption) ([]byte, error) {
	f.t.Logf("[test %s] Inside fixture installNoPkgManager function", f.t.Name())
	if installOpts == nil {
		// default options when not provided
		installOpts = &InstallOpts{}
	}

	// Removes install params to prevent enrollment
	removeEnrollParams := func(installOpts *InstallOpts) {
		installOpts.URL = ""
		installOpts.EnrollmentToken = ""
		installOpts.ESHost = ""
	}

	installArgs := []string{"install"}
	if !shouldEnroll {
		removeEnrollParams(installOpts)
	}

	installArgs = append(installArgs, installOpts.ToCmdArgs()...)
	out, err := f.Exec(ctx, installArgs, opts...)
	if err != nil {
		f.DumpProcesses("-install")
		return out, fmt.Errorf("error running agent install command: %w", err)
	}

	f.installed = true
	f.installOpts = installOpts

	installDir := "Agent"
	socketRunSymlink := paths.ControlSocketRunSymlink("")
	if installOpts.Namespace != "" {
		installDir = paths.InstallDirNameForNamespace(installOpts.Namespace)
		socketRunSymlink = paths.ControlSocketRunSymlink(installOpts.Namespace)
	}

	if installOpts.BasePath == "" {
		f.workDir = filepath.Join(paths.DefaultBasePath, "Elastic", installDir)
	} else {
		f.workDir = filepath.Join(installOpts.BasePath, "Elastic", installDir)
	}

	// we just installed agent, the control socket is at a well-known location
	socketPath := fmt.Sprintf("unix://%s", socketRunSymlink) // use symlink as that works for all versions
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
			f.DumpProcesses("-cleanup")
		}
	})

	f.t.Cleanup(func() {
		// check for running agents after uninstall had a chance to run
		processes := getElasticAgentProcesses(f.t)

		// there can be a single agent left when using --develop mode
		if f.installOpts != nil && f.installOpts.Namespace != "" {
			assert.LessOrEqualf(f.t, len(processes), 1, "More than one agent left running at the end of the test when second agent in namespace %s was used: %v", f.installOpts.Namespace, processes)
			// The agent left running has to be the non-development agent. The development agent should be uninstalled first as a convention.
			if len(processes) > 0 {
				assert.NotContainsf(f.t, processes[0].Cmdline, paths.InstallDirNameForNamespace(f.installOpts.Namespace),
					"The agent installed into namespace %s was left running at the end of the test or was not uninstalled first: %v", f.installOpts.Namespace, processes)
			}
			return
		}

		assert.Empty(f.t, processes, "there should be no running agent at the end of the test")
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
	if err != nil && assert.Truef(t, errors.Is(err, agentsystemprocess.NonFatalErr{}), "error fetching process information: %v", err) {
		// we failed a bit further
		return nil
	}

	processes := make([]runningProcess, 0, len(pids))

	for _, p := range pids {
		processes = append(processes, mapProcess(p))
	}

	return processes
}

// installDeb installs the prepared Elastic Agent binary from the deb
// package and registers a t.Cleanup function to uninstall the agent if
// it hasn't been uninstalled. It also takes care of collecting a
// diagnostics when AGENT_COLLECT_DIAG=true or the test has failed.
// It returns:
//   - the combined output of Install command stdout and stderr
//   - an error if any.
func (f *Fixture) installDeb(ctx context.Context, installOpts *InstallOpts, shouldEnroll bool, opts []process.CmdOption) ([]byte, error) {
	f.t.Logf("[test %s] Inside fixture installDeb function", f.t.Name())
	// Prepare so that the f.srcPackage string is populated
	err := f.EnsurePrepared(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare: %w", err)
	}

	// sudo apt-get install the deb
	out, err := exec.CommandContext(ctx, "sudo", "apt-get", "install", "-y", f.srcPackage).CombinedOutput() // #nosec G204 -- Need to pass in name of package
	if err != nil {
		return out, fmt.Errorf("apt install failed: %w output:%s", err, string(out))
	}

	f.t.Cleanup(func() {
		f.t.Logf("[test %s] Inside fixture installDeb cleanup function", f.t.Name())

		uninstallCtx, uninstallCancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer uninstallCancel()
		// stop elastic-agent, non fatal if error, might have been stopped before this.
		f.t.Logf("running 'sudo systemctl stop elastic-agent'")
		out, err := exec.CommandContext(uninstallCtx, "sudo", "systemctl", "stop", "elastic-agent").CombinedOutput()
		if err != nil {
			f.t.Logf("error systemctl stop elastic-agent: %s, output: %s", err, string(out))
		}

		if keepInstalledFlag() {
			f.t.Logf("skipping uninstall; test failed and AGENT_KEEP_INSTALLED=true")
			return
		}

		// apt-get purge elastic-agent
		f.t.Logf("running 'sudo apt-get -y -q purge elastic-agent'")
		out, err = exec.CommandContext(uninstallCtx, "sudo", "apt-get", "-y", "-q", "purge", "elastic-agent").CombinedOutput()
		if err != nil {
			f.t.Logf("failed to apt-get purge elastic-agent: %s, output: %s", err, string(out))
			f.t.FailNow()
		}
	})

	// start elastic-agent
	out, err = exec.CommandContext(ctx, "sudo", "systemctl", "start", "elastic-agent").CombinedOutput()
	if err != nil {
		return out, fmt.Errorf("systemctl start elastic-agent failed: %w", err)
	}

	if !shouldEnroll {
		return nil, nil
	}

	// apt install doesn't enroll, so need to do that
	enrollArgs := []string{"elastic-agent", "enroll"}
	if installOpts.Force {
		enrollArgs = append(enrollArgs, "--force")
	}
	if installOpts.Insecure {
		enrollArgs = append(enrollArgs, "--insecure")
	}
	if installOpts.ProxyURL != "" {
		enrollArgs = append(enrollArgs, "--proxy-url="+installOpts.ProxyURL)
	}
	if installOpts.DelayEnroll {
		enrollArgs = append(enrollArgs, "--delay-enroll")
	}
	if installOpts.EnrollOpts.URL != "" {
		enrollArgs = append(enrollArgs, "--url", installOpts.EnrollOpts.URL)
	}
	if installOpts.EnrollOpts.EnrollmentToken != "" {
		enrollArgs = append(enrollArgs, "--enrollment-token", installOpts.EnrollOpts.EnrollmentToken)
	}
	out, err = exec.CommandContext(ctx, "sudo", enrollArgs...).CombinedOutput()
	if err != nil {
		return out, fmt.Errorf("elastic-agent enroll failed: %w, output: %s args: %v", err, string(out), enrollArgs)
	}

	return nil, nil
}

// installRpm installs the prepared Elastic Agent binary from the rpm
// package and registers a t.Cleanup function to uninstall the agent if
// it hasn't been uninstalled. It also takes care of collecting a
// diagnostics when AGENT_COLLECT_DIAG=true or the test has failed.
// It returns:
//   - the combined output of Install command stdout and stderr
//   - an error if any.
func (f *Fixture) installRpm(ctx context.Context, installOpts *InstallOpts, shouldEnroll bool, opts []process.CmdOption) ([]byte, error) {
	f.t.Logf("[test %s] Inside fixture installRpm function", f.t.Name())
	// Prepare so that the f.srcPackage string is populated
	err := f.EnsurePrepared(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare: %w", err)
	}

	// sudo rpm -iv elastic-agent rpm
	out, err := exec.CommandContext(ctx, "sudo", "rpm", "-i", "-v", f.srcPackage).CombinedOutput() // #nosec G204 -- Need to pass in name of package
	if err != nil {
		return out, fmt.Errorf("rpm install failed: %w output:%s", err, string(out))
	}

	f.t.Cleanup(func() {
		f.t.Logf("[test %s] Inside fixture installRpm cleanup function", f.t.Name())

		uninstallCtx, uninstallCancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer uninstallCancel()
		// stop elastic-agent, non fatal if error, might have been stopped before this.
		f.t.Logf("running 'sudo systemctl stop elastic-agent'")
		out, err := exec.CommandContext(uninstallCtx, "sudo", "systemctl", "stop", "elastic-agent").CombinedOutput()
		if err != nil {
			f.t.Logf("error systemctl stop elastic-agent: %s, output: %s", err, string(out))
		}
		// rpm -e elastic-agent rpm
		f.t.Logf("running 'sudo rpm -e elastic-agent'")
		out, err = exec.CommandContext(uninstallCtx, "sudo", "rpm", "-e", "elastic-agent").CombinedOutput()
		if err != nil {
			f.t.Logf("failed to 'sudo rpm -e elastic-agent': %s, output: %s", err, string(out))
			f.t.FailNow()
		}

		f.t.Logf("removing installed agent files")
		out, err = exec.CommandContext(uninstallCtx, "sudo", "rm", "-rf", "/var/lib/elastic-agent", "/var/log/elastic-agent", "/etc/elastic-agent").CombinedOutput()
		if err != nil {
			f.t.Logf("failed to 'sudo rm -rf /var/lib/elastic-agent /var/log/elastic-agent/ /etc/elastic-agent'")
			f.t.FailNow()
		}
	})

	// start elastic-agent
	out, err = exec.CommandContext(ctx, "sudo", "systemctl", "start", "elastic-agent").CombinedOutput()
	if err != nil {
		return out, fmt.Errorf("systemctl start elastic-agent failed: %w", err)
	}

	if !shouldEnroll {
		return nil, nil
	}

	// rpm install doesn't enroll, so need to do that
	enrollArgs := []string{"elastic-agent", "enroll"}
	if installOpts.Force {
		enrollArgs = append(enrollArgs, "--force")
	}
	if installOpts.Insecure {
		enrollArgs = append(enrollArgs, "--insecure")
	}
	if installOpts.ProxyURL != "" {
		enrollArgs = append(enrollArgs, "--proxy-url="+installOpts.ProxyURL)
	}
	if installOpts.DelayEnroll {
		enrollArgs = append(enrollArgs, "--delay-enroll")
	}
	if installOpts.EnrollOpts.URL != "" {
		enrollArgs = append(enrollArgs, "--url", installOpts.EnrollOpts.URL)
	}
	if installOpts.EnrollOpts.EnrollmentToken != "" {
		enrollArgs = append(enrollArgs, "--enrollment-token", installOpts.EnrollOpts.EnrollmentToken)
	}
	// run sudo elastic-agent enroll
	out, err = exec.CommandContext(ctx, "sudo", enrollArgs...).CombinedOutput()
	if err != nil {
		return out, fmt.Errorf("elastic-agent enroll failed: %w, output: %s args: %v", err, string(out), enrollArgs)
	}

	return nil, nil
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
	switch f.packageFormat {
	case "targz", "zip":
		return f.uninstallNoPkgManager(ctx, uninstallOpts, opts)
	case "deb":
		return f.uninstallDeb(ctx, uninstallOpts, opts)
	case "rpm":
		return f.uninstallRpm(ctx, uninstallOpts, opts)
	default:
		return nil, fmt.Errorf("uninstall of package format '%s' not supported yet", f.packageFormat)
	}
}

func (f *Fixture) uninstallDeb(ctx context.Context, uninstallOpts *UninstallOpts, opts []process.CmdOption) ([]byte, error) {
	// stop elastic-agent, non fatal if error, might have been stopped before this.
	out, err := exec.CommandContext(ctx, "sudo", "systemctl", "stop", "elastic-agent").CombinedOutput()
	if err != nil {
		f.t.Logf("error systemctl stop elastic-agent: %s, output: %s", err, string(out))
	}
	out, err = exec.CommandContext(ctx, "sudo", "apt-get", "-y", "-q", "purge", "elastic-agent").CombinedOutput()
	if err != nil {
		return out, fmt.Errorf("error removing apt: %w", err)
	}
	return out, nil
}

func (f *Fixture) uninstallRpm(ctx context.Context, uninstallOpts *UninstallOpts, opts []process.CmdOption) ([]byte, error) {
	// stop elastic-agent, non fatal if error, might have been stopped before this.
	out, err := exec.CommandContext(ctx, "sudo", "systemctl", "stop", "elastic-agent").CombinedOutput()
	if err != nil {
		f.t.Logf("error systemctl stop elastic-agent: %s, output: %s", err, string(out))
	}
	out, err = exec.CommandContext(ctx, "sudo", "rpm", "-e", "elastic-agent").CombinedOutput()
	if err != nil {
		return out, fmt.Errorf("error running 'sudo rpm -e elastic-agent': %w", err)
	}
	return out, nil
}

func (f *Fixture) uninstallNoPkgManager(ctx context.Context, uninstallOpts *UninstallOpts, opts []process.CmdOption) ([]byte, error) {
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
	f.workDir = f.extractDir

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

	diagPath, err := f.DiagnosticsDir()
	if err != nil {
		f.t.Logf("failed to collect diagnostics: %v", err)
		return
	}

	err = os.MkdirAll(diagPath, 0755)
	if err != nil {
		f.t.Logf("failed to collect diagnostics; failed to create %s: %s", diagPath, err)
		return
	}

	prefix := f.FileNamePrefix()
	outputPath := filepath.Join(diagPath, prefix+"-diagnostics.zip")

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
			if err != nil {
				f.t.Logf("failed to collect diagnostics a second time at %s (%s): %s", outputPath, err, output)
			}
		}
		if err != nil {
			// If collecting diagnostics fails, zip up the entire installation directory with the hope that it will contain logs.
			f.t.Logf("creating zip archive of the installation directory: %s", f.workDir)
			zipPath := filepath.Join(diagPath, fmt.Sprintf("%s-install-directory.zip", prefix))
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

	walker := func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
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

	err = filepath.WalkDir(f.workDir, walker)
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
