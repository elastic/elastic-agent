// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package testing

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"

	"github.com/otiai10/copy"
	"gopkg.in/yaml.v2"

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
	f := &Fixture{
		t:               t,
		version:         version,
		caller:          caller,
		fetcher:         ArtifactFetcher(),
		operatingSystem: runtime.GOOS,
		architecture:    runtime.GOARCH,
		connectTimout:   5 * time.Second,
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
	workDir := f.t.TempDir()
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

	killProc := func() {
		_ = proc.Kill()
		<-proc.Wait()
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
		case ps := <-proc.Wait():
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

// RunWithClient runs the provided binary.
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
// if isClientEnabled is set to bool, communicating state does not happen.
func (f *Fixture) RunWithClient(ctx context.Context, isClientEnabled bool, states ...State) error {
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

	if isClientEnabled {
		agentClient = client.New(client.WithAddress(cAddr))
		f.setClient(agentClient)
		defer f.setClient(nil)
		stateCh, stateErrCh = watchState(ctx, agentClient, f.connectTimout)
	}

	var logProxy Logger
	if f.logOutput {
		logProxy = f.t
	}
	stdOut := newLogWatcher(logProxy)
	stdErr := newLogWatcher(logProxy)

	args := []string{"run", "-e", "--disable-encrypted-store", "--testing-mode"}

	args = append(args, f.additionalArgs...)

	proc, err := process.Start(
		f.binaryPath(),
		process.WithContext(ctx),
		process.WithArgs(args),
		process.WithCmdOptions(attachOutErr(stdOut, stdErr)))

	if err != nil {
		return fmt.Errorf("failed to spawn %s: %w", f.binaryName, err)
	}

	killProc := func() {
		_ = proc.Kill()
		<-proc.Wait()
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
		case ps := <-proc.Wait():
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
				cfg, cont, err := smInstance.next(state)
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
	return f.RunWithClient(ctx, true, states...)
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
	return e.err.Error()
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
// status successfully. Therefore, a not empty AgentStatusOutput is valid
// regardless of the error. An empty AgentStatusOutput and non nil error
// means the output could not be parsed.
// It should work with any 8.6+ agent
func (f *Fixture) ExecStatus(ctx context.Context, opts ...process.CmdOption) (AgentStatusOutput, error) {
	out, err := f.Exec(ctx, []string{"status", "--output", "json"}, opts...)
	status := AgentStatusOutput{}
	if uerr := json.Unmarshal(out, &status); uerr != nil {
		return AgentStatusOutput{},
			fmt.Errorf("could not unmarshal agent status output: %w",
				errors.Join(&ExecErr{
					err:    err,
					Output: out,
				}, uerr))
	}

	return status, err
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

// IsHealthy returns if the prepared Elastic Agent reports itself as healthy.
// It returns false, err if it cannot determine the state of the agent.
// It should work with any 8.6+ agent
func (f *Fixture) IsHealthy(ctx context.Context, opts ...process.CmdOption) (bool, error) {
	status, err := f.ExecStatus(ctx, opts...)
	if err != nil {
		return false, fmt.Errorf("agent status returned and error: %w", err)
	}

	return status.State == int(cproto.State_HEALTHY), nil
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
		if f.installOpts != nil && f.installOpts.BasePath != "" {
			workDir = filepath.Join(f.installOpts.BasePath, "Elastic", "Agent")
		} else {
			workDir = filepath.Join(paths.DefaultBasePath, "Elastic", "Agent")
		}
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

	res, err := f.fetcher.Fetch(ctx, f.operatingSystem, f.architecture, f.version)
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
	componentsDir, err := findComponentsDir(workDir)
	if err != nil {
		return err
	}
	contents, err := ioutil.ReadDir(componentsDir)
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

// findComponentsDir identifies the directory that holds the components.
func findComponentsDir(dir string) (string, error) {
	dataDir := filepath.Join(dir, "data")
	agentVersions, err := ioutil.ReadDir(dataDir)
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

func watchState(ctx context.Context, c client.Client, timeout time.Duration) (chan *client.AgentState, chan error) {
	stateCh := make(chan *client.AgentState)
	errCh := make(chan error)
	go func() {
		ctx, cancel := context.WithCancel(ctx)
		defer cancel()

		err := c.Connect(ctx)
		if err != nil {
			errCh <- err
			return
		}
		defer c.Disconnect()

		// StateWatch will return an error if the client is not fully connected
		// we retry this in a loop based on the timeout to ensure that we can
		// get a valid StateWatch connection
		started := time.Now()
		var sub client.ClientStateWatch
		for {
			sub, err = c.StateWatch(ctx)
			if err != nil {
				if time.Since(started) > timeout {
					// failed to connected in timeout range
					errCh <- err
					return
				}
				<-time.After(100 * time.Millisecond)
			} else {
				// connected successfully
				break
			}
		}

		for {
			recv, err := sub.Recv()
			if err != nil {
				errCh <- err
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
		ID        string `json:"id"`
		Version   string `json:"version"`
		Commit    string `json:"commit"`
		BuildTime string `json:"build_time"`
		Snapshot  bool   `json:"snapshot"`
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
	FleetState   int    `json:"FleetState"`
	FleetMessage string `json:"FleetMessage"`
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
