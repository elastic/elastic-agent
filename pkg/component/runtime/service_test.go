// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package runtime

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/elastic/elastic-agent-libs/api/npipe"

	"go.uber.org/zap/zapcore"

	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/elastic/elastic-agent-client/v7/pkg/proto"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/configuration"
	"github.com/elastic/elastic-agent/pkg/component"
	"github.com/elastic/elastic-agent/pkg/core/logger"
	"github.com/elastic/elastic-agent/pkg/core/logger/loggertest"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func makeComponent(name string, config map[string]interface{}) (component.Component, error) {
	c := component.Component{
		Units: []component.Unit{
			{
				Type:   client.UnitTypeInput,
				Config: &proto.UnitExpectedConfig{Type: name},
			},
		},
		InputSpec: &component.InputRuntimeSpec{
			Spec: component.InputSpec{
				Name: name,
			},
		},
	}
	unitCfg, err := component.ExpectedConfig(config)
	if err != nil {
		return c, err
	}
	c.Units[0].Config = unitCfg
	return c, nil
}

func makeEndpointComponent(t *testing.T, config map[string]interface{}) component.Component {
	comp, err := makeComponent("endpoint", config)
	if err != nil {
		t.Fatal(err)
	}
	return comp
}

func compareCompsConfigs(t *testing.T, comp component.Component, cfg map[string]interface{}) {
	for _, unit := range comp.Units {
		if unit.Type == client.UnitTypeInput {
			unitCfgMap := unit.Config.Source.AsMap()
			diff := cmp.Diff(cfg, unitCfgMap)
			if diff != "" {
				t.Fatal(diff)
			}
		}
	}
}

func TestInjectSigned(t *testing.T) {
	signed := &component.Signed{
		Data:      "eyJAdGltZXN0YW1wIjoiMjAyMy0wNS0yMlQxNzoxOToyOC40NjNaIiwiZXhwaXJhdGlvbiI6IjIwMjMtMDYtMjFUMTc6MTk6MjguNDYzWiIsImFnZW50cyI6WyI3ZjY0YWI2NC1hNmM0LTQ2ZTMtODIyYS0zODUxZGVkYTJmY2UiXSwiYWN0aW9uX2lkIjoiNGYwODQ2MGYtMDE0Yy00ZDllLWJmOGEtY2FhNjQyNzRhZGU0IiwidHlwZSI6IlVORU5ST0xMIiwidHJhY2VwYXJlbnQiOiIwMC1iOTBkYTlmOGNjNzdhODk0OTc0ZWIxZTIzMGNmNjc2Yy1lOTNlNzk4YTU4ODg2MDVhLTAxIn0=",
		Signature: "MEUCIAxxsi9ff1zyV0+4fsJLqbP8Qb83tedU5iIFldtxEzEfAiEA0KUsrL7q+Fv7z6Boux3dY2P4emGi71jsMGanIZ552bM=",
	}

	tests := []struct {
		name    string
		cfg     map[string]interface{}
		signed  *component.Signed
		wantCfg map[string]interface{}
	}{
		{
			name:    "nil signed",
			cfg:     map[string]interface{}{},
			wantCfg: map[string]interface{}{},
		},
		{
			name:   "signed",
			cfg:    map[string]interface{}{},
			signed: signed,
			wantCfg: map[string]interface{}{
				"signed": map[string]interface{}{
					"data":      "eyJAdGltZXN0YW1wIjoiMjAyMy0wNS0yMlQxNzoxOToyOC40NjNaIiwiZXhwaXJhdGlvbiI6IjIwMjMtMDYtMjFUMTc6MTk6MjguNDYzWiIsImFnZW50cyI6WyI3ZjY0YWI2NC1hNmM0LTQ2ZTMtODIyYS0zODUxZGVkYTJmY2UiXSwiYWN0aW9uX2lkIjoiNGYwODQ2MGYtMDE0Yy00ZDllLWJmOGEtY2FhNjQyNzRhZGU0IiwidHlwZSI6IlVORU5ST0xMIiwidHJhY2VwYXJlbnQiOiIwMC1iOTBkYTlmOGNjNzdhODk0OTc0ZWIxZTIzMGNmNjc2Yy1lOTNlNzk4YTU4ODg2MDVhLTAxIn0=",
					"signature": "MEUCIAxxsi9ff1zyV0+4fsJLqbP8Qb83tedU5iIFldtxEzEfAiEA0KUsrL7q+Fv7z6Boux3dY2P4emGi71jsMGanIZ552bM=",
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			newComp, err := injectSigned(makeEndpointComponent(t, tc.cfg), tc.signed)
			if err != nil {
				t.Fatal(err)
			}

			compareCompsConfigs(t, newComp, tc.wantCfg)
		})
	}

}

func TestResolveUninstallTokenArg(t *testing.T) {
	tests := []struct {
		name              string
		uninstallSpec     *component.ServiceOperationsCommandSpec
		uninstallToken    string
		wantUninstallSpec *component.ServiceOperationsCommandSpec
	}{
		{
			name: "nil uninstall spec",
		},
		{
			name: "no uninstall token",
			uninstallSpec: &component.ServiceOperationsCommandSpec{
				Args: []string{"uninstall", "--log", "stderr"},
			},
			wantUninstallSpec: &component.ServiceOperationsCommandSpec{
				Args: []string{"uninstall", "--log", "stderr"},
			},
		},
		{
			name: "with uninstall token arg and empty token value",
			uninstallSpec: &component.ServiceOperationsCommandSpec{
				Args: []string{"uninstall", "--log", "stderr", "--uninstall-token"},
			},
			wantUninstallSpec: &component.ServiceOperationsCommandSpec{
				Args: []string{"uninstall", "--log", "stderr"},
			},
		},
		{
			name: "with uninstall token arg and non-empty token value",
			uninstallSpec: &component.ServiceOperationsCommandSpec{
				Args: []string{"uninstall", "--log", "stderr", "--uninstall-token"},
			},
			uninstallToken: "placeholder",
			wantUninstallSpec: &component.ServiceOperationsCommandSpec{
				Args: []string{"uninstall", "--log", "stderr", "--uninstall-token", "placeholder"},
			},
		},
		{
			name: "with uninstall token args cap gt len",
			uninstallSpec: &component.ServiceOperationsCommandSpec{
				Args: func() []string {
					args := make([]string, 0, 8)
					args = append(args, "uninstall", "--log", "stderr", "--uninstall-token")
					return args
				}(),
			},
			uninstallToken: "placeholder",
			wantUninstallSpec: &component.ServiceOperationsCommandSpec{
				Args: []string{"uninstall", "--log", "stderr", "--uninstall-token", "placeholder"},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var originalUninstallSpec component.ServiceOperationsCommandSpec
			if tc.uninstallSpec != nil {
				originalUninstallSpec = *tc.uninstallSpec
			}
			spec := resolveUninstallTokenArg(tc.uninstallSpec, tc.uninstallToken)
			diff := cmp.Diff(tc.wantUninstallSpec, spec)
			if diff != "" {
				t.Fatal(diff)
			}

			// Test that the original spec was not changed
			if tc.uninstallSpec != nil {
				diff = cmp.Diff(originalUninstallSpec, *tc.uninstallSpec)
				if diff != "" {
					t.Fatal(diff)
				}
			}
		})
	}
}

func TestGetConnInfoServerAddress(t *testing.T) {
	tests := []struct {
		name     string
		os       string
		isLocal  bool
		port     int
		socket   string
		expected string
		wantErr  error
	}{
		{
			name:     "windows.port",
			os:       "windows",
			isLocal:  false,
			port:     6788,
			expected: "127.0.0.1:6788",
		},
		{
			name:     "unix.port",
			os:       "linux",
			isLocal:  false,
			port:     6788,
			expected: "127.0.0.1:6788",
		},
		{
			name:    "windows.local.socket.empty",
			os:      "windows",
			isLocal: true,
			wantErr: errEmptySocketValue,
		},
		{
			name:    "unix.local.socket.empty",
			os:      "linux",
			isLocal: true,
			wantErr: errEmptySocketValue,
		},
		{
			name:    "windows.local.socket",
			os:      "windows",
			isLocal: true,
			socket:  "test.sock",
			expected: func() string {
				u := url.URL{}
				u.Path = "/"
				u.Scheme = "npipe"
				return u.JoinPath("/", "test.sock").String()
			}(),
		},
		{
			name:    "unix.local.socket",
			os:      "linux",
			isLocal: true,
			socket:  "test.sock",
			expected: func() string {
				u := url.URL{}
				u.Path = "/"
				u.Scheme = "unix"
				return u.JoinPath(paths.Top(), "test.sock").String()
			}(),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			address, err := getConnInfoServerAddress(tc.os, tc.isLocal, tc.port, tc.socket)
			diff := cmp.Diff(tc.wantErr, err, cmpopts.EquateErrors())
			if diff != "" {
				t.Fatal(diff)
			}
			diff = cmp.Diff(address, tc.expected)
			if diff != "" {
				t.Error(diff)
			}
		})
	}
}

// dialConnInfoServer attempts a single connection to the connection-info server at
// cisAddr. The caller is responsible for closing a non-nil returned connection.
func dialConnInfoServer(ctx context.Context, cisAddr string) (net.Conn, error) {
	if runtime.GOOS != "windows" {
		parsedCISAddr, err := url.Parse(cisAddr)
		if err != nil {
			return nil, err
		}
		dialCtx, cancel := context.WithTimeout(ctx, time.Second)
		defer cancel()
		return (&net.Dialer{}).DialContext(dialCtx, "unix", parsedCISAddr.Host+parsedCISAddr.Path)
	}

	pipeAddr := cisAddr
	if strings.HasPrefix(pipeAddr, "npipe:///") {
		path := strings.TrimPrefix(pipeAddr, "npipe:///")
		pipeAddr = `\\.\pipe\` + path
	}
	return npipe.Dial(pipeAddr)("", "")
}

// TestCISKeepsRunningOnNonFatalExitCodeFromStart tests that the connection info
// server keeps running when starting a service component results in a non-fatal
// exit code.
func TestCISKeepsRunningOnNonFatalExitCodeFromStart(t *testing.T) {
	log, logObs := loggertest.New("test")
	const nonFatalExitCode = 99
	const cisPort = 9999
	const cisSocket = ".steaci.sock"

	// Make an Endpoint component for testing
	endpoint := makeEndpointComponent(t, map[string]interface{}{})
	endpoint.InputSpec.Spec.Service = &component.ServiceSpec{
		CPort:   cisPort,
		CSocket: cisSocket,
		Log:     nil,
		Operations: component.ServiceOperationsSpec{
			Check: &component.ServiceOperationsCommandSpec{},
			Install: &component.ServiceOperationsCommandSpec{
				NonFatalExitCodes: []int{nonFatalExitCode},
			},
		},
		Timeouts: component.ServiceTimeoutSpec{},
	}

	// Create binary mocking Endpoint such that executing it will return
	// the non-fatal exit code from the spec above.
	endpoint.InputSpec.BinaryPath = mockEndpointBinary(t, nonFatalExitCode)
	endpoint.InputSpec.BinaryName = "endpoint"

	t.Logf("mock binary path: %s\n", endpoint.InputSpec.BinaryPath)

	// Create new service runtime with component
	service, err := newServiceRuntime(endpoint, log, true)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	comm := newMockCommunicator("")

	// Observe component state
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-service.ch:
			}
		}
	}()

	// Run the service
	startServiceRuntime(t, ctx, cancel, service, comm)

	service.actionCh <- actionModeSigned{
		actionMode: actionStart,
	}

	// Check that connection info server is still running and that we see the
	// warning log message about Endpoint's install operation failing with a non-fatal exit
	// code but the service runtime continuing to run.
	cisAddr, err := getConnInfoServerAddress(runtime.GOOS, true, cisPort, cisSocket)
	require.NoError(t, err)

	// First, wait for the warning log message indicating the runtime continued
	// past the non-fatal install failure. Filtering the observer (rather than
	// draining it with TakeAll) means the assertion does not race with the
	// connection-server dial below.
	expectedWarnLogMsg := fmt.Sprintf("exit code %d is non-fatal, continuing to run...", nonFatalExitCode)
	require.Eventuallyf(t, func() bool {
		return logObs.FilterLevelExact(zapcore.WarnLevel).FilterMessage(expectedWarnLogMsg).Len() > 0
	}, 30*time.Second, 100*time.Millisecond, "did not observe expected non-fatal warn log %q", expectedWarnLogMsg)

	// Then verify the connection-info server is still accepting connections.
	// The dial is retried because on Windows winio's DialPipe can intermittently
	// return ERROR_PIPE_BUSY between Accept calls; the conn is closed each
	// attempt to avoid leaking client-side pipe handles.
	require.Eventuallyf(t, func() bool {
		conn, err := dialConnInfoServer(ctx, cisAddr)
		if err != nil {
			t.Logf("Connection info server is not running: %v", err)
			return false
		}
		_ = conn.Close()
		return true
	}, 30*time.Second, 1*time.Second, "connection info server did not accept a connection")
}

// TestServiceStartRetry tests that the service runtime will
// retry the service start command if it fails
func TestServiceStartRetry(t *testing.T) {
	log, logObs := loggertest.New("test")
	const cisPort = 9999
	const cisSocket = ".rteaci.sock"

	// Make an Endpoint component for testing
	endpoint := makeEndpointComponent(t, map[string]interface{}{})
	endpoint.InputSpec.Spec.Service = &component.ServiceSpec{
		CPort:   cisPort,
		CSocket: cisSocket,
		Log:     nil,
		Operations: component.ServiceOperationsSpec{
			Check:   &component.ServiceOperationsCommandSpec{},
			Install: &component.ServiceOperationsCommandSpec{},
		},
		Timeouts: component.ServiceTimeoutSpec{},
	}

	// Create binary mocking Endpoint such that executing it will return
	// the non-fatal exit code from the spec above.
	endpoint.InputSpec.BinaryPath = mockEndpointBinary(t, 99)
	endpoint.InputSpec.BinaryName = "endpoint"

	t.Logf("mock binary path: %s\n", endpoint.InputSpec.BinaryPath)

	// Create new service runtime with component
	service, err := newServiceRuntime(endpoint, log, true)
	require.NoError(t, err)

	// Shorten service restart delay for testing
	service.serviceRestartDelay = 2 * time.Second

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	comm := newMockCommunicator("")

	// Observe component state
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-service.ch:
			}
		}
	}()

	// Run the service runtime
	startServiceRuntime(t, ctx, cancel, service, comm)

	// Start the service
	service.actionCh <- actionModeSigned{
		actionMode: actionStart,
	}

	expectedRestartLogMsg := fmt.Sprintf(
		"failed to start endpoint service, err: %s, restarting after waiting for %v",
		"failed install endpoint service: exit status 99", service.serviceRestartDelay,
	)
	require.Eventually(t, func() bool {
		logs := logObs.TakeAll()
		for _, l := range logs {
			t.Logf("[%s] %s", l.Level, l.Message)
			if l.Level == zapcore.ErrorLevel && l.Message == expectedRestartLogMsg {
				return true
			}
		}
		return false
	}, service.serviceRestartDelay+1*time.Second, 500*time.Millisecond)
}

// TestServiceStartFailureReportedAcrossRetries tests that a failed service start
// is reported as FAILED and that the retries do not reset the state to STARTING.
func TestServiceStartFailureReportedAcrossRetries(t *testing.T) {
	log, logObs := loggertest.New("test")

	endpoint := makeEndpointComponent(t, map[string]interface{}{})
	endpoint.InputSpec.Spec.Service = &component.ServiceSpec{
		CPort:   9999,
		CSocket: ".sfrteaci.sock",
		Operations: component.ServiceOperationsSpec{
			Check:   &component.ServiceOperationsCommandSpec{},
			Install: &component.ServiceOperationsCommandSpec{},
		},
	}
	endpoint.InputSpec.BinaryPath = mockEndpointBinary(t, 99)
	endpoint.InputSpec.BinaryName = "endpoint"

	service, err := newServiceRuntime(endpoint, log, true)
	require.NoError(t, err)
	service.serviceRestartDelay = 500 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var mu sync.Mutex
	var states []client.UnitState
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case st := <-service.ch:
				mu.Lock()
				states = append(states, st.State)
				mu.Unlock()
			}
		}
	}()

	startServiceRuntime(t, ctx, cancel, service, newMockCommunicator(""))
	service.actionCh <- actionModeSigned{actionMode: actionStart}

	// Wait for at least two failed attempts, i.e. one retry happened.
	require.Eventually(t, func() bool {
		return logObs.FilterLevelExact(zapcore.ErrorLevel).
			FilterMessageSnippet("failed to start endpoint service").Len() >= 2
	}, 30*time.Second, 100*time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	require.Equal(t, client.UnitStateStarting, states[0])
	require.Contains(t, states, client.UnitStateFailed)
	failedAt := slices.Index(states, client.UnitStateFailed)
	for _, st := range states[failedAt:] {
		require.Equal(t, client.UnitStateFailed, st, "retry must not reset the state from FAILED")
	}
}

// startServiceRuntime runs service.Run in the background and registers a cleanup
// that cancels ctx and waits for Run to return. Cancelling the context alone does not
// wait for the connection-info server to close, and tests share socket names across
// runs; Run's deferred cleanup closes the server before it returns, so waiting for it
// guarantees no server outlives the test.
func startServiceRuntime(t *testing.T, ctx context.Context, cancel context.CancelFunc, service *serviceRuntime, comm Communicator) {
	t.Helper()
	runDone := make(chan error, 1)
	go func() { runDone <- service.Run(ctx, comm) }()
	t.Cleanup(func() {
		cancel()
		// No local timeout: a fixed deadline could fail spuriously on a loaded CI
		// runner, and a real hang is already caught by the go test timeout.
		//
		// Keep draining the unbuffered state channel while waiting: the tests'
		// observer goroutines exit on ctx.Done(), and Run may still publish a final
		// state while shutting down, which would otherwise block it forever.
		for {
			select {
			case <-service.ch:
			case err := <-runDone:
				require.ErrorIs(t, err, context.Canceled)
				return
			}
		}
	})
}

func makeServiceForCheckStatus(t *testing.T, installTimeout, uninstallTimeout, checkTimeout time.Duration) *serviceRuntime {
	log, _ := loggertest.New("test")
	endpoint := makeEndpointComponent(t, map[string]interface{}{})
	endpoint.InputSpec.Spec.Service = &component.ServiceSpec{
		CPort:   9999,
		CSocket: ".test.sock",
		Operations: component.ServiceOperationsSpec{
			Check:     &component.ServiceOperationsCommandSpec{Timeout: checkTimeout},
			Install:   &component.ServiceOperationsCommandSpec{Timeout: installTimeout},
			Uninstall: &component.ServiceOperationsCommandSpec{Timeout: uninstallTimeout},
		},
	}

	service, err := newServiceRuntime(endpoint, log, true)
	require.NoError(t, err)
	// simulate the service already being up and running
	service.state.State = client.UnitStateHealthy

	// drain state updates so compState/forceCompState never block on service.ch
	done := make(chan struct{})
	t.Cleanup(func() { close(done) })
	go func() {
		for {
			select {
			case <-done:
				return
			case <-service.ch:
			}
		}
	}()

	return service
}

// TestUpgradeGracePeriodExceedsMaxServiceTimeout ensures the default upgrade
// watcher grace period always exceeds the longest service operation timeout so
// a service that never checks back in is still caught before the watcher gives up.
// It loads the real endpoint-security spec so a spec change that breaks the
// invariant fails this test.
func TestUpgradeGracePeriodExceedsMaxServiceTimeout(t *testing.T) {
	specData, err := os.ReadFile(filepath.Join("..", "..", "..", "specs", "endpoint-security.spec.yml"))
	require.NoError(t, err, "reading endpoint-security.spec.yml")
	spec, err := component.LoadSpec(specData)
	require.NoError(t, err, "parsing endpoint-security.spec.yml")

	var maxTimeout time.Duration
	for _, input := range spec.Inputs {
		if input.Service == nil {
			continue
		}
		ops := input.Service.Operations
		for _, op := range []*component.ServiceOperationsCommandSpec{ops.Check, ops.Install} {
			if op != nil && op.Timeout > maxTimeout {
				maxTimeout = op.Timeout
			}
		}
	}
	require.NotZero(t, maxTimeout, "endpoint spec must have at least one service operation timeout")

	gracePeriod := configuration.DefaultUpgradeConfig().Watcher.GracePeriod
	require.Greater(t, gracePeriod, maxTimeout,
		"upgrade watcher grace period (%v) must exceed max service operation timeout (%v)", gracePeriod, maxTimeout)
}

func TestServiceCheckinFailureTimeout(t *testing.T) {
	service := makeServiceForCheckStatus(t, 600*time.Second, 600*time.Second, 60*time.Second)
	require.Equal(t, 600*time.Second, service.checkinFailureTimeout())
	require.Equal(t, 20, service.maxCheckinMisses(30*time.Second))

	// falls back to the generic count when nothing is configured
	noTimeouts := makeServiceForCheckStatus(t, 0, 0, 0)
	require.Equal(t, time.Duration(0), noTimeouts.checkinFailureTimeout())
	require.Equal(t, maxCheckinMisses, noTimeouts.maxCheckinMisses(30*time.Second))
}

func TestServiceCheckStatus(t *testing.T) {
	const checkinPeriod = 30 * time.Second

	t.Run("normal check-in stays healthy", func(t *testing.T) {
		service := makeServiceForCheckStatus(t, 600*time.Second, 600*time.Second, 60*time.Second)
		lastCheckin := time.Now()
		missedCheckins := 0

		service.checkStatus(checkinPeriod, &lastCheckin, &missedCheckins)

		require.Equal(t, client.UnitStateHealthy, service.state.State)
		require.Equal(t, 0, missedCheckins)
	})

	t.Run("slow but within configured operation timeout stays degraded", func(t *testing.T) {
		service := makeServiceForCheckStatus(t, 600*time.Second, 600*time.Second, 60*time.Second)
		lastCheckin := time.Now().Add(-150 * time.Second)
		missedCheckins := 0

		// past the old 90s window, but well under the 600s timeout
		for i := 0; i < 5; i++ {
			service.checkStatus(checkinPeriod, &lastCheckin, &missedCheckins)
		}

		require.Equal(t, client.UnitStateDegraded, service.state.State)
	})

	t.Run("stuck past the configured operation timeout is marked failed", func(t *testing.T) {
		service := makeServiceForCheckStatus(t, 600*time.Second, 600*time.Second, 60*time.Second)
		lastCheckin := time.Now().Add(-660 * time.Second)
		missedCheckins := 0

		// past the 600s timeout
		for i := 0; i < 22; i++ {
			service.checkStatus(checkinPeriod, &lastCheckin, &missedCheckins)
		}

		require.Equal(t, client.UnitStateFailed, service.state.State)
	})

	t.Run("component with no configured operation timeouts keeps the generic 90s failure window", func(t *testing.T) {
		service := makeServiceForCheckStatus(t, 0, 0, 0)
		lastCheckin := time.Now().Add(-120 * time.Second)
		missedCheckins := 0

		// past the generic 90s window
		for i := 0; i < 4; i++ {
			service.checkStatus(checkinPeriod, &lastCheckin, &missedCheckins)
		}

		require.Equal(t, client.UnitStateFailed, service.state.State)
	})
}

func mockEndpointBinary(t *testing.T, exitCode int) string {
	// Build a mock Endpoint binary that can return a specific exit code.
	outPath := filepath.Join(t.TempDir(), "mock_endpoint")
	if runtime.GOOS == "windows" {
		outPath += ".exe"
	}

	cmd := exec.CommandContext(
		t.Context(),
		"go", "build",
		"-o", outPath,
		"-ldflags", "-X 'main.ExitCode="+strconv.Itoa(exitCode)+"'",
		"testdata/exitcode/main.go",
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	require.NoError(t, err)

	return outPath
}

// TestConnInfoServerClosedDuringInstall verifies that the connection-info server (CIS)
// does not accept connections while the installer for a service component is running,
// and becomes reachable only once the installer completes successfully.
//
// Regression: PR #9313 opened the CIS before running the installer. A still-running old
// service (e.g. the previous Endpoint version) could dial in while the new version was
// still installing, be adopted as HEALTHY, and receive a policy update that interfered
// with the upgrade (SDH-854). This test exercises the real connInfoServer and address,
// not a mock, so it directly verifies the open/close ordering rather than the drain
// logic (see TestStaleCheckinDrainedOnInstallRetry for that).
func TestConnInfoServerClosedDuringInstall(t *testing.T) {
	log, _ := loggertest.New("test")
	const cisPort = 9995
	const cisSocket = ".tciclosed.sock"

	endpoint := makeEndpointComponent(t, map[string]interface{}{})
	endpoint.InputSpec.Spec.Service = &component.ServiceSpec{
		CPort:   cisPort,
		CSocket: cisSocket,
		Operations: component.ServiceOperationsSpec{
			Check:   &component.ServiceOperationsCommandSpec{},
			Install: &component.ServiceOperationsCommandSpec{},
		},
	}

	service, err := newServiceRuntime(endpoint, log, true)
	require.NoError(t, err)

	var startOnce sync.Once
	installStarted := make(chan struct{})
	releaseInstall := make(chan struct{})
	firstCall := true // first call is always check; subsequent calls are install

	service.executeServiceCommandImpl = func(ctx context.Context, _ *logger.Logger, _ string, _ *component.ServiceOperationsCommandSpec) error {
		if firstCall {
			firstCall = false
			return errors.New("service not installed") // check fails → install is triggered
		}
		startOnce.Do(func() { close(installStarted) })
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-releaseInstall:
		}
		return nil // install succeeds
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	comm := newMockCommunicator("")

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-service.ch:
			}
		}
	}()

	startServiceRuntime(t, ctx, cancel, service, comm)

	service.actionCh <- actionModeSigned{actionMode: actionStart}

	select {
	case <-installStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("install did not start within timeout")
	}

	cisAddr, err := getConnInfoServerAddress(runtime.GOOS, true, cisPort, cisSocket)
	require.NoError(t, err)

	// While the installer is still running, the CIS must not exist yet: this is the
	// core guarantee of the ordering fix, and the reason the old service can no
	// longer be adopted mid-install.
	_, dialErr := dialConnInfoServer(ctx, cisAddr)
	require.Error(t, dialErr, "connection-info server must not accept connections while the installer is running")

	close(releaseInstall)

	// Once the installer completes successfully, the CIS should come up and accept
	// connections.
	require.Eventually(t, func() bool {
		conn, err := dialConnInfoServer(ctx, cisAddr)
		if err != nil {
			return false
		}
		_ = conn.Close()
		return true
	}, 30*time.Second, 100*time.Millisecond, "connection info server did not accept a connection after install completed")
}

// TestStaleCheckinDrainedOnInstallRetry verifies that a checkin left over from a
// previous connection-info server (CIS) instance is drained and discarded rather
// than adopted, before a failed install is retried.
//
// This does not exercise the CIS open/close ordering itself (see
// TestConnInfoServerClosedDuringInstall for that): it injects the stale checkin
// directly into the communicator channel to isolate the drain logic, which matters
// on a retry where a previous CIS instance had already accepted a connection and
// queued a checkin before this attempt's cisStop() tore it down.
func TestStaleCheckinDrainedOnInstallRetry(t *testing.T) {
	log, _ := loggertest.New("test")

	endpoint := makeEndpointComponent(t, map[string]interface{}{})
	endpoint.InputSpec.Spec.Service = &component.ServiceSpec{
		CPort:   9996,
		CSocket: ".testraceinstall.sock",
		Operations: component.ServiceOperationsSpec{
			Check:   &component.ServiceOperationsCommandSpec{},
			Install: &component.ServiceOperationsCommandSpec{},
		},
	}

	service, err := newServiceRuntime(endpoint, log, true)
	require.NoError(t, err)
	// Long retry delay so the automatic retry doesn't interfere with the assertion window.
	service.serviceRestartDelay = 30 * time.Second

	var startOnce, doneOnce sync.Once
	installStarted := make(chan struct{})
	installDone := make(chan struct{})
	firstCall := true // first call is always check; subsequent calls are install

	service.executeServiceCommandImpl = func(ctx context.Context, _ *logger.Logger, _ string, _ *component.ServiceOperationsCommandSpec) error {
		if firstCall {
			firstCall = false
			return errors.New("service not installed") // check fails → install is triggered
		}
		startOnce.Do(func() { close(installStarted) })
		defer doneOnce.Do(func() { close(installDone) })
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
		return errors.New("install failed") // simulate exit 284
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	comm := newMockCommunicator("")

	statesCh := make(chan ComponentState, 50)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case s := <-service.ch:
				select {
				case statesCh <- s:
				default:
				}
			}
		}
	}()

	startServiceRuntime(t, ctx, cancel, service, comm)

	service.actionCh <- actionModeSigned{actionMode: actionStart}

	select {
	case <-installStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("install did not start within timeout")
	}

	// Simulate the old service reconnecting to the CIS mid-install.
	// In production this happens because the old service is still running as a
	// system service and reconnects when the new agent opens the named pipe.
	comm.ch <- &proto.CheckinObserved{}

	select {
	case <-installDone:
	case <-time.After(5 * time.Second):
		t.Fatal("install did not complete within timeout")
	}

	// The old service's checkin must be drained and discarded, never processed.
	// If the runtime adopts it as HEALTHY the fix is not in effect.
	require.Never(t, func() bool {
		select {
		case s := <-statesCh:
			return s.State == client.UnitStateHealthy
		default:
			return false
		}
	}, 500*time.Millisecond, 10*time.Millisecond,
		"old service was incorrectly adopted as HEALTHY while the installer was running")
}
