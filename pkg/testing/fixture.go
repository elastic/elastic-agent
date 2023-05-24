// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package testing

import (
	"context"
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

	"github.com/otiai10/copy"
	"gopkg.in/yaml.v2"

	"github.com/elastic/elastic-agent/pkg/component"
	"github.com/elastic/elastic-agent/pkg/control"
	"github.com/elastic/elastic-agent/pkg/control/v2/client"
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

	workDir string

	installed   bool
	installOpts *InstallOpts

	c   client.Client
	cMx sync.RWMutex
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

// WithConnectTimeout adjusts the timeout for connecting to the spawned Elastic Agent control protocol.
// By default, the timeout is 5 seconds.
func WithConnectTimeout(timeout time.Duration) FixtureOpt {
	return func(f *Fixture) {
		f.connectTimout = timeout
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
// This must be called before `Run` or `Install` can be called. `components` defines the components that you want to
// be prepared for the Elastic Agent. See the definition on defining usable components on the `UsableComponent`
// structure.
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
	filename := filepath.Base(src)
	name, ext, err := splitFileType(filename)
	if err != nil {
		return err
	}
	workDir := f.t.TempDir()
	finalDir := filepath.Join(workDir, name)
	f.t.Logf("Extracting artifact %s to %s", filename, finalDir)
	switch ext {
	case ".tar.gz":
		err := untar(src, workDir)
		if err != nil {
			return fmt.Errorf("failed to untar %s: %w", src, err)
		}
	case ".zip":
		err := unzip(src, workDir)
		if err != nil {
			return fmt.Errorf("failed to unzip %s: %w", src, err)
		}
	}
	f.t.Logf("Completed extraction of artifact %s to %s", filename, finalDir)
	err = f.prepareComponents(finalDir, components...)
	if err != nil {
		return err
	}
	f.workDir = finalDir
	return nil
}

// Run runs the Elastic Agent.
//
// If `states` are provided then the Elastic Agent runs until each state has been reached. Once reached the
// Elastic Agent is stopped. If at any time the Elastic Agent logs an error log and the Fixture is not started
// with `WithAllowErrors()` then `Run` will exit early and return the logged error.
//
// If no `states` are provided then the Elastic Agent runs until the context is cancelled.
func (f *Fixture) Run(ctx context.Context, states ...State) error {
	if f.installed {
		return errors.New("fixture is installed; cannot be run")
	}

	var err error
	err = f.ensurePrepared(ctx)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var sm *stateMachine
	if states != nil {
		sm, err = newStateMachine(states)
		if err != nil {
			return err
		}
	}

	var logProxy Logger
	if f.logOutput {
		logProxy = f.t
	}
	stdOut := newLogWatcher(logProxy)
	stdErr := newLogWatcher(logProxy)

	cAddr, err := control.AddressFromPath(f.operatingSystem, f.workDir)
	if err != nil {
		return fmt.Errorf("failed to get control protcol address: %w", err)
	}

	proc, err := process.Start(
		f.binaryPath(),
		process.WithContext(ctx),
		process.WithArgs([]string{"run", "-e", "--disable-encrypted-store", "--testing-mode"}),
		process.WithCmdOptions(attachOutErr(stdOut, stdErr)))
	if err != nil {
		return fmt.Errorf("failed to spawn elastic-agent: %w", err)
	}
	killProc := func() {
		_ = proc.Kill()
		<-proc.Wait()
	}

	c := client.New(client.WithAddress(cAddr))
	f.setClient(c)
	defer f.setClient(nil)

	stateCh, stateErrCh := watchState(ctx, c, f.connectTimout)
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
		case state := <-stateCh:
			if sm != nil {
				cfg, cont, err := sm.next(state)
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
					err := performConfigure(ctx, c, cfg, 3*time.Second)
					if err != nil {
						killProc()
						return err
					}
				}
			}
		}
	}
}

// Exec provides a way of performing subcommand on the prepared Elastic Agent binary.
func (f *Fixture) Exec(ctx context.Context, args []string, opts ...process.CmdOption) ([]byte, error) {
	err := f.ensurePrepared(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare before exec: %w", err)
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// #nosec G204 -- Not so many ways to support variadic arguments to the elastic-agent command :(
	cmd := exec.CommandContext(ctx, f.binaryPath(), args...)
	for _, o := range opts {
		if err := o(cmd); err != nil {
			return nil, fmt.Errorf("error adding opts to Exec: %w", err)
		}
	}
	f.t.Logf(">> running agent with: %v", cmd.Args)

	return cmd.CombinedOutput()
}

func (f *Fixture) ensurePrepared(ctx context.Context) error {
	if f.workDir == "" {
		return f.Prepare(ctx)
	}
	return nil
}

func (f *Fixture) binaryPath() string {
	binary := filepath.Join(f.workDir, "elastic-agent")
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
		f.t.Logf("Components where not modified from the fetched artifact")
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
		if err := os.Chown(destBinary, os.Geteuid(), os.Getgid()); err != nil {
			return fmt.Errorf("failed to chown %s: %w", destBinary, err)
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
