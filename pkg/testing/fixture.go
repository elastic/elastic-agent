// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package testing

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/otiai10/copy"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v2"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/details"
	"github.com/elastic/elastic-agent/pkg/component"
	"github.com/elastic/elastic-agent/pkg/control"
	"github.com/elastic/elastic-agent/pkg/control/v2/client"
	"github.com/elastic/elastic-agent/pkg/control/v2/cproto"
	"github.com/elastic/elastic-agent/pkg/core/process"
)

// Fixture handles the setup and management of the Elastic Agent.
type Fixture struct {
	t       *testing.T
	version string
	caller  string

	fetcher         Fetcher
	operatingSystem string
	architecture    string
	packageFormat   string
	logOutput       bool
	allowErrs       bool
	connectTimout   time.Duration
	binaryName      string
	runLength       time.Duration
	additionalArgs  []string

	srcPackage string
	workDir    string

	installed   bool
	installOpts *InstallOpts

	c   client.Client
	cMx sync.RWMutex

	// Uninstall token value that is needed for the agent uninstall if it's tamper protected
	uninstallToken string
}

// FixtureOpt is an option for the fixture.
type FixtureOpt func(s *Fixture)

// WithFetcher changes the fetcher that is used for the fixture.
func WithFetcher(fetcher Fetcher) FixtureOpt {
	if fetcher == nil {
		panic("fetcher cannot be nil")
	}
	return func(f *Fixture) {
		f.fetcher = fetcher
	}
}

// WithOSArchitecture changes the operating system and the architecture to use for the fixture.
// By default, the runtime operating system and the architecture is selected.
func WithOSArchitecture(operatingSystem string, architecture string) FixtureOpt {
	return func(f *Fixture) {
		f.operatingSystem = operatingSystem
		f.architecture = architecture
	}
}

// WithPackageFormat changes the package format to use for the fixture.
// By default, targz is picked except for windows which uses zip
func WithPackageFormat(packageFormat string) FixtureOpt {
	return func(f *Fixture) {
		f.packageFormat = packageFormat
	}
}

// WithLogOutput instructs the fixture to log all Elastic Agent output to the test log.
// By default, the Elastic Agent output will not be logged to the test logger.
func WithLogOutput() FixtureOpt {
	return func(f *Fixture) {
		f.logOutput = true
	}
}

// WithAllowErrors instructs the fixture to allow the Elastic Agent to log errors.
// By default, the Fixture will not allow the Elastic Agent to log any errors, logging any error
// will result on the Fixture to kill the Elastic Agent and report it as an error.
func WithAllowErrors() FixtureOpt {
	return func(f *Fixture) {
		f.allowErrs = true
	}
}

// WithConnectTimeout changes the timeout for connecting to the spawned Elastic Agent control protocol.
// By default, the timeout is 5 seconds.
func WithConnectTimeout(timeout time.Duration) FixtureOpt {
	return func(f *Fixture) {
		f.connectTimout = timeout
	}
}

// WithBinaryName sets the name of the binary under test, in cases where tests aren't being run against elastic-agent
func WithBinaryName(name string) FixtureOpt {
	return func(f *Fixture) {
		f.binaryName = name
	}
}

// WithRunLength sets the total time the binary will run
func WithRunLength(run time.Duration) FixtureOpt {
	return func(f *Fixture) {
		f.runLength = run
	}
}

func WithAdditionalArgs(args []string) FixtureOpt {
	return func(f *Fixture) {
		f.additionalArgs = args
	}
}

// NewFixture creates a new fixture to setup and manage Elastic Agent.
func NewFixture(t *testing.T, version string, opts ...FixtureOpt) (*Fixture, error) {
	// we store the caller so the fixture can find the cache directory for the artifacts that
	// are used for the testing with the Elastic Agent.
	//
	// runtime.Caller(1) is used because we want the filename of the caller, not the path of
	// our self on the filesystem.
	_, caller, _, ok := runtime.Caller(1)
	if !ok {
		return nil, errors.New("unable to determine callers file path")
	}
	pkgFormat := "targz"
	if runtime.GOOS == "windows" {
		pkgFormat = "zip"
	}
	f := &Fixture{
		t:               t,
		version:         version,
		caller:          caller,
		fetcher:         ArtifactFetcher(),
		operatingSystem: runtime.GOOS,
		architecture:    runtime.GOARCH,
		packageFormat:   pkgFormat,
		connectTimout:   15 * time.Second,
		// default to elastic-agent, can be changed by a set FixtureOpt below
		binaryName: "elastic-agent",
	}
	for _, o := range opts {
		o(f)
	}
	return f, nil
}

// Client returns the Elastic Agent communication client.
func (f *Fixture) Client() client.Client {
	f.cMx.RLock()
	defer f.cMx.RUnlock()
	return f.c
}

// Prepare prepares the Elastic Agent for usage.
//
// This must be called before `Configure`, `Run`, or `Install` can be called.
// `components` defines the components that you want to be prepared for the
// Elastic Agent. See the definition on defining usable components on the
// `UsableComponent` structure.
//
// Note: If no `components` are defined then the Elastic Agent will keep all the components that are shipped with the
// fetched build of the Elastic Agent.
func (f *Fixture) Prepare(ctx context.Context, components ...UsableComponent) error {
	err := validateComponents(components...)
	if err != nil {
		return err
	}
	if f.workDir != "" {
		// already prepared
		return fmt.Errorf("already been prepared")
	}
	src, err := f.fetch(ctx)
	if err != nil {
		return err
	}
	f.srcPackage = src
	filename := filepath.Base(src)
	name, _, err := splitFileType(filename)
	if err != nil {
		return err
	}
	workDir := createTempDir(f.t)
	finalDir := filepath.Join(workDir, name)
	err = ExtractArtifact(f.t, src, workDir)
	if err != nil {
		return fmt.Errorf("extracting artifact %q in %q: %w", src, workDir, err)
	}
	err = f.prepareComponents(finalDir, components...)
	if err != nil {
		return err
	}
	f.workDir = finalDir
	return nil
}

// createTempDir creates a temporary directory that will be
// removed after the tests passes.
//
// If the test fails, the temporary directory is not removed.
//
// If the tests are run with -v, the temporary directory will
// be logged.
func createTempDir(t *testing.T) string {
	tempDir, err := os.MkdirTemp("", strings.ReplaceAll(t.Name(), "/", "-"))
	if err != nil {
		t.Fatalf("failed to make temp directory: %s", err)
	}

	cleanup := func() {
		if !t.Failed() {
			if err := os.RemoveAll(tempDir); err != nil {
				t.Errorf("could not remove temp dir '%s': %s", tempDir, err)
			}
		} else {
			t.Logf("Temporary directory saved: %s", tempDir)
		}
	}
	t.Cleanup(cleanup)

	return tempDir
}

// WriteFileToWorkDir sends a file to the working directory alongside the unpacked tar build.
func (f *Fixture) WriteFileToWorkDir(ctx context.Context, data string, name string) error {
	err := f.EnsurePrepared(ctx)
	if err != nil {
		return fmt.Errorf("error preparing binary: %w", err)
	}

	err = os.WriteFile(filepath.Join(f.workDir, name), []byte(data), 0644)
	if err != nil {
		return fmt.Errorf("error writing file: %w", err)
	}
	f.t.Logf("wrote %s to %s", name, f.workDir)
	return nil
}

// Configure replaces the default Agent configuration file with the provided
// configuration. This must be called after `Prepare` is called but before `Run`
// or `Install` can be called.
func (f *Fixture) Configure(ctx context.Context, yamlConfig []byte) error {
	err := f.EnsurePrepared(ctx)
	if err != nil {
		return err
	}

	cfgFilePath := filepath.Join(f.workDir, "elastic-agent.yml")
	return os.WriteFile(cfgFilePath, yamlConfig, 0600)
}

// SetUninstallToken sets uninstall token
func (f *Fixture) SetUninstallToken(uninstallToken string) {
	f.uninstallToken = uninstallToken
}

// WorkDir returns the installed fixture's work dir AKA base dir AKA top dir. This
// must be called after `Install` is called.
func (f *Fixture) WorkDir() string {
	return f.workDir
}

// SrcPackage returns the location on disk of the elastic agent package used by this fixture.
func (f *Fixture) SrcPackage(ctx context.Context) (string, error) {
	err := f.EnsurePrepared(ctx)
	if err != nil {
		return "", err
	}
	return f.srcPackage, nil
}

// PackageFormat returns the package format for the  fixture
func (f *Fixture) PackageFormat() string {
	return f.packageFormat
}

func ExtractArtifact(l Logger, artifactFile, outputDir string) error {
	filename := filepath.Base(artifactFile)
	_, ext, err := splitFileType(filename)
	if err != nil {
		return err
	}
	l.Logf("Extracting artifact %s to %s", filename, outputDir)
	switch ext {
	case ".tar.gz":
		err := untar(artifactFile, outputDir)
		if err != nil {
			return fmt.Errorf("failed to untar %s: %w", artifactFile, err)
		}
	case ".zip":
		err := unzip(artifactFile, outputDir)
		if err != nil {
			return fmt.Errorf("failed to unzip %s: %w", artifactFile, err)
		}
	case ".deb", "rpm":
		err := copy.Copy(artifactFile, filepath.Join(outputDir, filepath.Base(artifactFile)))
		if err != nil {
			return fmt.Errorf("failed to copy %s to %s: %w", artifactFile, outputDir, err)
		}
	}
	l.Logf("Completed extraction of artifact %s to %s", filename, outputDir)
	return nil
}

// RunBeat runs the given given beat
// the beat will run until an error, or the given timeout is reached
func (f *Fixture) RunBeat(ctx context.Context) error {
	if f.binaryName == "elastic-agent" {
		return errors.New("RunBeat() can't be run against elastic-agent")
	}

	if _, deadlineSet := ctx.Deadline(); !deadlineSet {
		f.t.Fatal("Context passed to Fixture.RunBeat() has no deadline set.")
	}

	var err error
	err = f.EnsurePrepared(ctx)
	if err != nil {
		return fmt.Errorf("error preparing beat: %w", err)
	}

	var logProxy Logger
	if f.logOutput {
		logProxy = f.t
	}
	stdOut := newLogWatcher(logProxy)
	stdErr := newLogWatcher(logProxy)
	args := []string{"run", "-e", "-c", filepath.Join(f.workDir, fmt.Sprintf("%s.yml", f.binaryName))}

	args = append(args, f.additionalArgs...)

	proc, err := process.Start(
		f.binaryPath(),
		process.WithContext(ctx),
		process.WithArgs(args),
		process.WithCmdOptions(attachOutErr(stdOut, stdErr)))

	if err != nil {
		return fmt.Errorf("failed to spawn %s: %w", f.binaryName, err)
	}

	procWaitCh := proc.Wait()
	killProc := func() {
		_ = proc.Kill()
		<-procWaitCh
	}

	var doneChan <-chan time.Time
	if f.runLength != 0 {
		doneChan = time.After(f.runLength)
	}

	stopping := false
	for {
		select {
		case <-ctx.Done():
			killProc()
			return ctx.Err()
		case ps := <-procWaitCh:
			if stopping {
				return nil
			}
			return fmt.Errorf("elastic-agent exited unexpectedly with exit code: %d", ps.ExitCode())
		case err := <-stdOut.Watch():
			if !f.allowErrs {
				// no errors allowed
				killProc()
				return fmt.Errorf("elastic-agent logged an unexpected error: %w", err)
			}
		case err := <-stdErr.Watch():
			if !f.allowErrs {
				// no errors allowed
				killProc()
				return fmt.Errorf("elastic-agent logged an unexpected error: %w", err)
			}
		case <-doneChan:
			if !stopping {
				// trigger the stop
				stopping = true
				_ = proc.Stop()
			}
		}
	}
}

// RunProcess runs the given given process
// the process will run until an error, or the given timeout is reached
func RunProcess(t *testing.T,
	lp Logger,
	ctx context.Context, runLength time.Duration,
	logOutput, allowErrs bool,
	processPath string, args ...string) error {
	if _, deadlineSet := ctx.Deadline(); !deadlineSet {
		t.Fatal("Context passed to RunProcess() has no deadline set.")
	}

	var err error
	var logProxy Logger
	if logOutput {
		logProxy = lp
	}
	stdOut := newLogWatcher(logProxy)
	stdErr := newLogWatcher(logProxy)

	proc, err := process.Start(
		processPath,
		process.WithContext(ctx),
		process.WithArgs(args),
		process.WithCmdOptions(attachOutErr(stdOut, stdErr)))

	if err != nil {
		return fmt.Errorf("failed to spawn %q: %w", processPath, err)
	}

	procWaitCh := proc.Wait()
	killProc := func() {
		_ = proc.Kill()
		<-procWaitCh
	}

	var doneChan <-chan time.Time
	if runLength != 0 {
		doneChan = time.After(runLength)
	}

	stopping := false
	for {
		select {
		case <-ctx.Done():
			killProc()
			return ctx.Err()
		case ps := <-procWaitCh:
			if stopping {
				return nil
			}
			return fmt.Errorf("elastic-agent exited unexpectedly with exit code: %d", ps.ExitCode())
		case err := <-stdOut.Watch():
			if !allowErrs {
				// no errors allowed
				killProc()
				return fmt.Errorf("elastic-agent logged an unexpected error: %w", err)
			}
		case err := <-stdErr.Watch():
			if !allowErrs {
				// no errors allowed
				killProc()
				return fmt.Errorf("elastic-agent logged an unexpected error: %w", err)
			}
		case <-doneChan:
			if !stopping {
				// trigger the stop
				stopping = true
				_ = proc.Stop()
			}
		}
	}
}

// RunOtelWithClient runs the provided binary in otel mode.
//
// If `states` are provided, agent runs until each state has been reached. Once reached the
// Elastic Agent is stopped. If at any time the Elastic Agent logs an error log and the Fixture is not started
// with `WithAllowErrors()` then `Run` will exit early and return the logged error.
//
// If no `states` are provided then the Elastic Agent runs until the context is cancelled.
//
// The Elastic-Agent is started agent in test mode (--testing-mode) this mode
// expects the initial configuration (full YAML config) via gRPC.
// This configuration should be passed in the State.Configure field.
//
// The `elastic-agent.yml` generated by `Fixture.Configure` is ignored
// when `Run` is called.
//
// if shouldWatchState is set to false, communicating state does not happen.
func (f *Fixture) RunOtelWithClient(ctx context.Context, shouldWatchState bool, enableTestingMode bool, states ...State) error {
	return f.executeWithClient(ctx, "otel", false, shouldWatchState, enableTestingMode, states...)
}

func (f *Fixture) executeWithClient(ctx context.Context, command string, disableEncryptedStore bool, shouldWatchState bool, enableTestingMode bool, states ...State) error {
	if _, deadlineSet := ctx.Deadline(); !deadlineSet {
		f.t.Fatal("Context passed to Fixture.Run() has no deadline set.")
	}

	if f.binaryName != "elastic-agent" {
		return errors.New("Run() can only be used with elastic-agent, use RunBeat()")
	}
	if f.installed {
		return errors.New("fixture is installed; cannot be run")
	}

	var err error
	err = f.EnsurePrepared(ctx)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var smInstance *stateMachine
	if states != nil {
		smInstance, err = newStateMachine(states)
		if err != nil {
			return err
		}
	}

	// agent-specific setup
	var agentClient client.Client
	var stateCh chan *client.AgentState
	var stateErrCh chan error

	cAddr, err := control.AddressFromPath(f.operatingSystem, f.workDir)
	if err != nil {
		return fmt.Errorf("failed to get control protcol address: %w", err)
	}

	var logProxy Logger
	if f.logOutput {
		logProxy = f.t
	}
	stdOut := newLogWatcher(logProxy)
	stdErr := newLogWatcher(logProxy)

	args := []string{command, "-e"}
	if disableEncryptedStore {
		args = append(args, "--disable-encrypted-store")
	}
	if enableTestingMode {
		args = append(args, "--testing-mode")
	}

	args = append(args, f.additionalArgs...)

	proc, err := process.Start(
		f.binaryPath(),
		process.WithContext(ctx),
		process.WithArgs(args),
		process.WithCmdOptions(attachOutErr(stdOut, stdErr)))

	if err != nil {
		return fmt.Errorf("failed to spawn %s: %w", f.binaryName, err)
	}

	if shouldWatchState {
		agentClient = client.New(client.WithAddress(cAddr))
		f.setClient(agentClient)
		defer f.setClient(nil)
		stateCh, stateErrCh = watchState(ctx, f.t, agentClient, f.connectTimout)
	}

	var doneChan <-chan time.Time
	if f.runLength != 0 {
		doneChan = time.After(f.runLength)
	}

	procWaitCh := proc.Wait()
	killProc := func() {
		_ = proc.Kill()
		<-procWaitCh
	}

	stopping := false
	for {
		select {
		case <-ctx.Done():
			killProc()
			return ctx.Err()
		case ps := <-procWaitCh:
			if stopping {
				return nil
			}
			return fmt.Errorf("elastic-agent exited unexpectedly with exit code: %d", ps.ExitCode())
		case err := <-stdOut.Watch():
			if !f.allowErrs {
				// no errors allowed
				killProc()
				return fmt.Errorf("elastic-agent logged an unexpected error: %w", err)
			}
		case err := <-stdErr.Watch():
			if !f.allowErrs {
				// no errors allowed
				killProc()
				return fmt.Errorf("elastic-agent logged an unexpected error: %w", err)
			}
		case err := <-stateErrCh:
			if !stopping {
				// Give the log watchers a second to write out the agent logs.
				// Client connnection failures can happen quickly enough to prevent logging.
				time.Sleep(time.Second)
				// connection to elastic-agent failed
				killProc()
				return fmt.Errorf("elastic-agent client received unexpected error: %w", err)
			}
		case <-doneChan:
			if !stopping {
				// trigger the stop
				stopping = true
				_ = proc.Stop()
			}
		case state := <-stateCh:
			if smInstance != nil {
				cfg, cont, err := smInstance.next(ctx, state)
				if err != nil {
					killProc()
					return fmt.Errorf("state management failed with unexpected error: %w", err)
				}
				if !cont {
					if !stopping {
						// trigger the stop
						stopping = true
						_ = proc.Stop()
					}
				} else if cfg != "" {
					err := performConfigure(ctx, agentClient, cfg, 3*time.Second)
					if err != nil {
						killProc()
						return err
					}
				}
			}
		}
	}
}

// Run runs the provided binary.
//
// If `states` are provided, agent runs until each state has been reached. Once reached the
// Elastic Agent is stopped. If at any time the Elastic Agent logs an error log and the Fixture is not started
// with `WithAllowErrors()` then `Run` will exit early and return the logged error.
//
// If no `states` are provided then the Elastic Agent runs until the context is cancelled.
//
// The Elastic-Agent is started agent in test mode (--testing-mode) this mode
// expects the initial configuration (full YAML config) via gRPC.
// This configuration should be passed in the State.Configure field.
//
// The `elastic-agent.yml` generated by `Fixture.Configure` is ignored
// when `Run` is called.
func (f *Fixture) Run(ctx context.Context, states ...State) error {
	return f.executeWithClient(ctx, "run", true, true, true, states...)
}

// Exec provides a way of performing subcommand on the prepared Elastic Agent binary.
func (f *Fixture) Exec(ctx context.Context, args []string, opts ...process.CmdOption) ([]byte, error) {
	err := f.EnsurePrepared(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare before exec: %w", err)
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	cmd, err := f.PrepareAgentCommand(ctx, args, opts...)
	if err != nil {
		return nil, fmt.Errorf("error creating cmd: %w", err)
	}
	f.t.Logf(">> running binary with: %v", cmd.Args)

	return cmd.CombinedOutput()
}

// PrepareAgentCommand creates an exec.Cmd ready to execute an elastic-agent command.
func (f *Fixture) PrepareAgentCommand(ctx context.Context, args []string, opts ...process.CmdOption) (*exec.Cmd, error) {
	err := f.EnsurePrepared(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare before exec: %w", err)
	}

	// #nosec G204 -- Not so many ways to support variadic arguments to the elastic-agent command :(
	cmd := exec.CommandContext(ctx, f.binaryPath(), args...)
	for _, o := range opts {
		if err := o(cmd); err != nil {
			return nil, fmt.Errorf("error adding opts to Exec: %w", err)
		}
	}
	return cmd, nil
}

type ExecErr struct {
	err    error
	Output []byte
}

func (e *ExecErr) Error() string {
	return e.String()
}

func (e *ExecErr) String() string {
	return fmt.Sprintf("error: %v, output: %s", e.err, e.Output)
}

func (e *ExecErr) As(target any) bool {
	switch target.(type) {
	case *ExecErr:
		target = e
		return true
	case ExecErr:
		target = *e
		return true
	default:
		return errors.As(e.err, &target)
	}
}

func (e *ExecErr) Unwrap() error {
	return e.err
}

// ExecStatus executes the status subcommand on the prepared Elastic Agent binary.
// It returns the parsed output and the error from the execution. Keep in mind
// the agent exits with status 1 if it's unhealthy, but it still outputs the
// status successfully. An empty AgentStatusOutput and non nil error
// means the output could not be parsed.
// As long as we get some output, we don't return any error.
// It should work with any 8.6+ agent
func (f *Fixture) ExecStatus(ctx context.Context, opts ...process.CmdOption) (AgentStatusOutput, error) {
	out, err := f.Exec(ctx, []string{"status", "--output", "json"}, opts...)
	status := AgentStatusOutput{}
	if uerr := json.Unmarshal(out, &status); uerr != nil {
		return AgentStatusOutput{},
			fmt.Errorf("could not unmarshal agent status output: %w", errors.Join(uerr, err))
	} else if status.IsZero() {
		return status, fmt.Errorf("agent status output is empty: %w", err)
	}

	return status, nil
}

// ExecInspect executes to inspect subcommand on the prepared Elastic Agent binary.
// It returns the parsed output and the error from the execution or an empty
// AgentInspectOutput and the unmarshalling error if it cannot unmarshal the
// output.
// It should work with any 8.6+ agent
func (f *Fixture) ExecInspect(ctx context.Context, opts ...process.CmdOption) (AgentInspectOutput, error) {
	out, err := f.Exec(ctx, []string{"inspect"}, opts...)
	inspect := AgentInspectOutput{}
	if uerr := yaml.Unmarshal(out, &inspect); uerr != nil {
		return AgentInspectOutput{},
			fmt.Errorf("could not unmarshal agent inspect output: %w",
				errors.Join(&ExecErr{
					err:    err,
					Output: out,
				}, uerr))
	}

	return inspect, err
}

// ExecVersion executes the version subcommand on the prepared Elastic Agent binary
// with '--binary-only'. It returns the parsed YAML output.
func (f *Fixture) ExecVersion(ctx context.Context, opts ...process.CmdOption) (AgentVersionOutput, error) {
	out, err := f.Exec(ctx, []string{"version", "--binary-only", "--yaml"}, opts...)
	version := AgentVersionOutput{}
	if uerr := yaml.Unmarshal(out, &version); uerr != nil {
		return AgentVersionOutput{},
			fmt.Errorf("could not unmarshal agent version output: %w",
				errors.Join(&ExecErr{
					err:    err,
					Output: out,
				}, uerr))
	}

	return version, err
}

// ExecDiagnostics executes the agent diagnostic and returns the path to the
// zip file. If no cmd is provided, `diagnostics` will be used as the default.
// The working directory of the command will be set to a temporary directory.
// Use extractZipArchive to extract the diagnostics archive.
func (f *Fixture) ExecDiagnostics(ctx context.Context, cmd ...string) (string, error) {
	t := f.t
	t.Helper()

	if len(cmd) == 0 {
		cmd = []string{"diagnostics"}
	}

	wd := t.TempDir()
	diagnosticCmdOutput, err := f.Exec(ctx, cmd, process.WithWorkDir(wd))

	t.Logf("diagnostic command completed with output \n%q\n", diagnosticCmdOutput)
	require.NoErrorf(t, err, "error running diagnostic command: %v", err)

	t.Logf("checking directory %q for the generated diagnostics archive", wd)
	files, err := filepath.Glob(filepath.Join(wd, "elastic-agent-diagnostics-*.zip"))
	require.NoError(t, err)
	require.Len(t, files, 1)

	t.Logf("Found %q diagnostic archive.", files[0])

	return files[0], err
}

// IsHealthy checks whether the prepared Elastic Agent reports itself as healthy.
// It returns an error if either the reported state isn't healthy or if it fails
// to fetch the current state. If the status is successfully fetched, but it
// isn't healthy, the error will contain the reported status.
// This function is compatible with any Elastic Agent version 8.6 or later.
func (f *Fixture) IsHealthy(ctx context.Context, opts ...process.CmdOption) error {
	status, err := f.ExecStatus(ctx, opts...)
	if err != nil {
		return fmt.Errorf("agent status returned an error: %w", err)
	}

	if status.State != int(cproto.State_HEALTHY) {
		return fmt.Errorf("agent isn't healthy, current status: %s",
			client.State(status.State))
	}

	return nil
}

// IsInstalled returns true if this fixture has been installed
func (f *Fixture) IsInstalled() bool {
	return f.installed
}

// EnsurePrepared ensures that the fixture has been prepared.
func (f *Fixture) EnsurePrepared(ctx context.Context) error {
	if f.workDir == "" {
		return f.Prepare(ctx)
	}
	return nil
}

func (f *Fixture) binaryPath() string {
	workDir := f.workDir
	if f.installed {
		installDir := "Agent"
		if f.installOpts != nil && f.installOpts.Namespace != "" {
			installDir = paths.InstallDirNameForNamespace(f.installOpts.Namespace)
		}

		if f.installOpts != nil && f.installOpts.BasePath != "" {
			workDir = filepath.Join(f.installOpts.BasePath, "Elastic", installDir)
		} else {
			workDir = filepath.Join(paths.DefaultBasePath, "Elastic", installDir)
		}
	}
	if f.packageFormat == "deb" || f.packageFormat == "rpm" {
		workDir = "/usr/bin"
	}
	defaultBin := "elastic-agent"
	if f.binaryName != "" {
		defaultBin = f.binaryName
	}
	binary := filepath.Join(workDir, defaultBin)
	if f.operatingSystem == "windows" {
		binary += ".exe"
	}
	return binary
}

func (f *Fixture) fetch(ctx context.Context) (string, error) {
	cache := f.getFetcherCache()
	cache.mx.Lock()
	defer cache.mx.Unlock()

	if cache.dir == "" {
		// set the directory for the artifacts for this fetcher
		// the contents are placed local to the project so that on debugging
		// of tests the same contents are used for each run
		dir, err := getCacheDir(f.caller, f.fetcher.Name())
		if err != nil {
			return "", fmt.Errorf("failed to get directory for fetcher %s: %w", f.fetcher.Name(), err)
		}
		cache.dir = dir
	}

	res, err := f.fetcher.Fetch(ctx, f.operatingSystem, f.architecture, f.version, f.packageFormat)
	if err != nil {
		return "", err
	}
	path, err := cache.fetch(ctx, f.t, res)
	if err != nil {
		return "", err
	}
	return path, nil
}

func (f *Fixture) getFetcherCache() *fetcherCache {
	fetchCacheMx.Lock()
	defer fetchCacheMx.Unlock()

	if fetchCache == nil {
		fetchCache = make(map[string]*fetcherCache)
	}

	cache, ok := fetchCache[f.fetcher.Name()]
	if !ok {
		cache = &fetcherCache{}
		fetchCache[f.fetcher.Name()] = cache
	}

	return cache
}

func (f *Fixture) prepareComponents(workDir string, components ...UsableComponent) error {
	if len(components) == 0 {
		f.t.Logf("Components were not modified from the fetched artifact")
		return nil
	}

	// determine the components to keep
	keep := make(map[string]bool)
	for _, comp := range components {
		if comp.BinaryPath == "" {
			keep[comp.Name] = false
		}
	}

	// now remove all that should not be kept; removal is only
	// done by removing the spec file, no need to delete the binary
	componentsDir, err := FindComponentsDir(workDir)
	if err != nil {
		return err
	}
	contents, err := os.ReadDir(componentsDir)
	if err != nil {
		return fmt.Errorf("failed to read contents of components directory %s: %w", componentsDir, err)
	}
	var kept []string
	for _, fi := range contents {
		if fi.IsDir() {
			// ignore directories (only care about specification files)
			continue
		}
		name := fi.Name()
		if !strings.HasSuffix(name, ".spec.yml") {
			// ignore other files (only care about specification files)
			continue
		}
		name = strings.TrimSuffix(name, ".spec.yml")
		_, ok := keep[name]
		if !ok {
			// specification file is not marked to keep, so we remove it
			// so the Elastic Agent doesn't know how to run that component
			deleteFile := filepath.Join(componentsDir, fi.Name())
			if err := os.Remove(deleteFile); err != nil {
				return fmt.Errorf("failed to delete component specification %s: %w", deleteFile, err)
			}
		} else {
			kept = append(kept, name)
			keep[name] = true
		}
	}
	var missing []string
	for name, found := range keep {
		if !found {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("failed to find defined usable components: %s", strings.Join(missing, ", "))
	}
	if len(kept) == 0 {
		f.t.Logf("All component specifications where removed")
	} else {
		f.t.Logf("All component specifications where removed except: %s", strings.Join(kept, ", "))
	}

	// place the components that should be set to be usable by the Elastic Agent
	var placed []string
	for _, comp := range components {
		if comp.BinaryPath == "" {
			continue
		}
		destBinary := filepath.Join(componentsDir, comp.Name)
		if f.operatingSystem == "windows" {
			destBinary += ".exe"
		}
		if err := copy.Copy(comp.BinaryPath, destBinary); err != nil {
			return fmt.Errorf("failed to copy %s to %s: %w", comp.BinaryPath, destBinary, err)
		}
		if runtime.GOOS != "windows" {
			// chown is not supported on Windows
			if err := os.Chown(destBinary, os.Geteuid(), os.Getgid()); err != nil {
				return fmt.Errorf("failed to chown %s: %w", destBinary, err)
			}
		}
		if err := os.Chmod(destBinary, 0755); err != nil {
			return fmt.Errorf("failed to chmod %s: %w", destBinary, err)
		}
		destSpec := filepath.Join(componentsDir, fmt.Sprintf("%s.spec.yml", comp.Name))
		if comp.SpecPath != "" {
			if err := copy.Copy(comp.SpecPath, destSpec); err != nil {
				return fmt.Errorf("failed to copy %s to %s: %w", comp.SpecPath, destSpec, err)
			}
		} else if comp.Spec != nil {
			if err := writeSpecFile(destSpec, comp.Spec); err != nil {
				return fmt.Errorf("failed to write specification file %s: %w", destSpec, err)
			}
		}
		placed = append(placed, comp.Name)

	}
	if len(placed) > 0 {
		f.t.Logf("Placed component specifications: %s", strings.Join(placed, ", "))
	}

	return nil
}

func (f *Fixture) setClient(c client.Client) {
	f.cMx.Lock()
	defer f.cMx.Unlock()
	f.c = c
}

func (f *Fixture) DumpProcesses(suffix string) {
	procs := getProcesses(f.t, `.*`)
	dir, err := findProjectRoot(f.caller)
	if err != nil {
		f.t.Logf("failed to dump process; failed to find project root: %s", err)
		return
	}

	// Sub-test names are separated by "/" characters which are not valid filenames on Linux.
	sanitizedTestName := strings.ReplaceAll(f.t.Name(), "/", "-")

	filePath := filepath.Join(dir, "build", "diagnostics", fmt.Sprintf("TEST-%s-%s-%s-ProcessDump%s.json", sanitizedTestName, f.operatingSystem, f.architecture, suffix))
	fileDir := path.Dir(filePath)
	if err := os.MkdirAll(fileDir, 0777); err != nil {
		f.t.Logf("failed to dump process; failed to create directory %s: %s", fileDir, err)
		return
	}

	f.t.Logf("Dumping running processes in %s", filePath)
	file, err := os.OpenFile(filePath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		f.t.Logf("failed to dump process; failed to create output file %s root: %s", filePath, err)
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

// validateComponents ensures that the provided UsableComponent's are valid.
func validateComponents(components ...UsableComponent) error {
	for idx, comp := range components {
		name := comp.Name
		if name == "" {
			name = fmt.Sprintf("component %d", idx)
		}
		err := comp.Validate()
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	return nil
}

// findProjectRoot searches the project to find the go.mod file that is defined
// at the root of the project.
func findProjectRoot(caller string) (string, error) {
	dir := caller
	for {
		dir = filepath.Dir(dir)
		fi, err := os.Stat(filepath.Join(dir, "go.mod"))
		if (err == nil || os.IsExist(err)) && !fi.IsDir() {
			return dir, nil
		}
		if strings.HasSuffix(dir, string(filepath.Separator)) {
			// made it to root directory
			return "", fmt.Errorf("unable to find golang root directory from caller path %s", caller)
		}
	}
}

// getCacheDir returns the cache directory that a fetcher uses to store its fetched artifacts.
func getCacheDir(caller string, name string) (string, error) {
	dir, err := findProjectRoot(caller)
	if err != nil {
		return "", err
	}
	cacheDir := filepath.Join(dir, ".agent-testing", name)
	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		return "", fmt.Errorf("failed creating directory %s: %w", cacheDir, err)
	}
	return cacheDir, nil
}

// FindComponentsDir identifies the directory that holds the components.
func FindComponentsDir(dir string) (string, error) {
	dataDir := filepath.Join(dir, "data")
	agentVersions, err := os.ReadDir(dataDir)
	if err != nil {
		return "", fmt.Errorf("failed to read contents of the data directory %s: %w", dataDir, err)
	}
	var versionDir string
	for _, fi := range agentVersions {
		if strings.HasPrefix(fi.Name(), "elastic-agent-") && fi.IsDir() {
			versionDir = fi.Name()
			break
		}
	}
	componentsDir := filepath.Join(dataDir, versionDir, "components")
	fi, err := os.Stat(componentsDir)
	if (err != nil && !os.IsExist(err)) || !fi.IsDir() {
		return "", fmt.Errorf("failed to find components directory at %s: %w", componentsDir, err)
	}
	return componentsDir, nil
}

// writeSpecFile writes the specification to a specification file at the defined destination.
func writeSpecFile(dest string, spec *component.Spec) error {
	data, err := yaml.Marshal(spec)
	if err != nil {
		return err
	}
	specWriter, err := os.OpenFile(dest, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer specWriter.Close()
	_, err = specWriter.Write(data)
	if err != nil {
		return err
	}
	return nil
}

// attachOutErr attaches the logWatcher to std out and std error of the spawned process.
func attachOutErr(stdOut *logWatcher, stdErr *logWatcher) process.CmdOption {
	return func(cmd *exec.Cmd) error {
		cmd.Stdout = stdOut
		cmd.Stderr = stdErr
		return nil
	}
}

func watchState(ctx context.Context, t *testing.T, c client.Client, timeout time.Duration) (chan *client.AgentState, chan error) {
	stateCh := make(chan *client.AgentState)
	errCh := make(chan error)

	go func() {
		err := c.Connect(ctx)
		if err != nil {
			errCh <- fmt.Errorf("Connect() failed: %w", err)
			return
		}
		defer c.Disconnect()

		// StateWatch will return an error if the client is not fully connected
		// we retry this in a loop based on the timeout to ensure that we can
		// get a valid StateWatch connection
		var sub client.ClientStateWatch
		expBackoff := backoff.NewExponentialBackOff()
		expBackoff.InitialInterval = 100 * time.Millisecond
		expBackoff.MaxElapsedTime = timeout
		expBackoff.MaxInterval = 2 * time.Second
		err = backoff.RetryNotify(
			func() error {
				var err error
				sub, err = c.StateWatch(ctx)
				return err
			},
			backoff.WithContext(expBackoff, ctx),
			func(err error, retryAfter time.Duration) {
				t.Logf("%s: StateWatch failed: %s retrying: %s", time.Now().UTC().Format(time.RFC3339Nano), err.Error(), retryAfter)
			},
		)
		if err != nil {
			errCh <- fmt.Errorf("StateWatch() failed: %w", err)
			return
		}

		t.Logf("%s: StateWatch started", time.Now().UTC().Format(time.RFC3339Nano))
		for {
			recv, err := sub.Recv()
			if err != nil {
				errCh <- fmt.Errorf("Recv() failed: %w", err)
				return
			}
			stateCh <- recv
		}
	}()
	return stateCh, errCh
}

func performConfigure(ctx context.Context, c client.Client, cfg string, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	err := c.Configure(ctx, cfg)
	if err != nil {
		return fmt.Errorf("state management failed update configuration: %w", err)
	}
	return nil
}

type AgentStatusOutput struct {
	Info struct {
		ID           string `json:"id"`
		Version      string `json:"version"`
		Commit       string `json:"commit"`
		BuildTime    string `json:"build_time"`
		Snapshot     bool   `json:"snapshot"`
		PID          int32  `json:"pid"`
		Unprivileged bool   `json:"unprivileged"`
	} `json:"info"`
	State      int    `json:"state"`
	Message    string `json:"message"`
	Components []struct {
		ID      string `json:"id"`
		Name    string `json:"name"`
		State   int    `json:"state"`
		Message string `json:"message"`
		Units   []struct {
			UnitID   string `json:"unit_id"`
			UnitType int    `json:"unit_type"`
			State    int    `json:"state"`
			Message  string `json:"message"`
			Payload  struct {
				OsqueryVersion string `json:"osquery_version"`
			} `json:"payload"`
		} `json:"units"`
		VersionInfo struct {
			Name    string `json:"name"`
			Version string `json:"version"`
			Meta    struct {
				BuildTime string `json:"build_time"`
				Commit    string `json:"commit"`
			} `json:"meta"`
		} `json:"version_info,omitempty"`
	} `json:"components"`
	FleetState     int              `json:"FleetState"`
	FleetMessage   string           `json:"FleetMessage"`
	UpgradeDetails *details.Details `json:"upgrade_details"`
}

func (aso *AgentStatusOutput) IsZero() bool {
	return aso.Info.ID == "" && aso.Message == "" && aso.Info.Version == ""
}

type AgentInspectOutput struct {
	Agent struct {
		Download struct {
			SourceURI string `yaml:"sourceURI"`
		} `yaml:"download"`
		Features interface{} `yaml:"features"`
		Headers  interface{} `yaml:"headers"`
		ID       string      `yaml:"id"`
		Logging  struct {
			Level string `yaml:"level"`
		} `yaml:"logging"`
		Monitoring struct {
			Enabled bool `yaml:"enabled"`
			HTTP    struct {
				Buffer  interface{} `yaml:"buffer"`
				Enabled bool        `yaml:"enabled"`
				Host    string      `yaml:"host"`
				Port    int         `yaml:"port"`
			} `yaml:"http"`
			Logs      bool   `yaml:"logs"`
			Metrics   bool   `yaml:"metrics"`
			Namespace string `yaml:"namespace"`
			UseOutput string `yaml:"use_output"`
		} `yaml:"monitoring"`
		Protection struct {
			Enabled            bool   `yaml:"enabled"`
			SigningKey         string `yaml:"signing_key"`
			UninstallTokenHash string `yaml:"uninstall_token_hash"`
		} `yaml:"protection"`
	} `yaml:"agent"`
	Fleet struct {
		AccessAPIKey string `yaml:"access_api_key"`
		Agent        struct {
			ID string `yaml:"id"`
		} `yaml:"agent"`
		Enabled   bool     `yaml:"enabled"`
		Host      string   `yaml:"host"`
		Hosts     []string `yaml:"hosts"`
		Protocol  string   `yaml:"protocol"`
		ProxyURL  string   `yaml:"proxy_url"`
		Reporting struct {
			CheckFrequencySec int `yaml:"check_frequency_sec"`
			Threshold         int `yaml:"threshold"`
		} `yaml:"reporting"`
		Ssl struct {
			Renegotiation    string `yaml:"renegotiation"`
			VerificationMode string `yaml:"verification_mode"`
		} `yaml:"ssl"`
		Timeout string `yaml:"timeout"`
	} `yaml:"fleet"`
	Host struct {
		ID string `yaml:"id"`
	} `yaml:"host"`
	ID      string      `yaml:"id"`
	Inputs  interface{} `yaml:"inputs"`
	Outputs struct {
		Default struct {
			APIKey string   `yaml:"api_key"`
			Hosts  []string `yaml:"hosts"`
			Type   string   `yaml:"type"`
		} `yaml:"default"`
	} `yaml:"outputs"`
	Path struct {
		Config string `yaml:"config"`
		Data   string `yaml:"data"`
		Home   string `yaml:"home"`
		Logs   string `yaml:"logs"`
	} `yaml:"path"`
	Revision int `yaml:"revision"`
	Runtime  struct {
		Arch   string `yaml:"arch"`
		Os     string `yaml:"os"`
		Osinfo struct {
			Family  string `yaml:"family"`
			Major   int    `yaml:"major"`
			Minor   int    `yaml:"minor"`
			Patch   int    `yaml:"patch"`
			Type    string `yaml:"type"`
			Version string `yaml:"version"`
		} `yaml:"osinfo"`
	} `yaml:"runtime"`
	Signed struct {
		Data string `yaml:"data"`
	} `yaml:"signed"`
}

type AgentBinaryVersion struct {
	Version   string `yaml:"version"`
	Commit    string `yaml:"commit"`
	BuildTime string `yaml:"build_time"`
	Snapshot  bool   `yaml:"snapshot"`
}

// String returns the version string.
func (v *AgentBinaryVersion) String() string {
	s := v.Version
	if v.Snapshot {
		s += "-SNAPSHOT"
	}
	return s
}

type AgentVersionOutput struct {
	Binary AgentBinaryVersion `yaml:"binary"`
}
