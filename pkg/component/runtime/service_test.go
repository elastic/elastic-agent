// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package runtime

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/elastic/elastic-agent-libs/api/npipe"

	"go.uber.org/zap/zapcore"

	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/elastic/elastic-agent-client/v7/pkg/proto"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/pkg/component"
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
			uninstallToken: "EQo1ML2T95pdcH",
			wantUninstallSpec: &component.ServiceOperationsCommandSpec{
				Args: []string{"uninstall", "--log", "stderr", "--uninstall-token", "EQo1ML2T95pdcH"},
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
			uninstallToken: "EQo1ML2T95pdcH",
			wantUninstallSpec: &component.ServiceOperationsCommandSpec{
				Args: []string{"uninstall", "--log", "stderr", "--uninstall-token", "EQo1ML2T95pdcH"},
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
	go func() {
		err := service.Run(ctx, comm)
		require.EqualError(t, err, context.Canceled.Error())
	}()

	service.actionCh <- actionModeSigned{
		actionMode: actionStart,
	}

	// Check that connection info server is still running and that we see the
	// warning log message about Endpoint's install operation failing with a non-fatal exit
	// code but the service runtime continuing to run.
	cisAddr, err := getConnInfoServerAddress(runtime.GOOS, true, cisPort, cisSocket)
	require.NoError(t, err)

	parsedCISAddr, err := url.Parse(cisAddr)
	require.NoError(t, err)

	expectedWarnLogMsg := fmt.Sprintf("exit code %d is non-fatal, continuing to run...", nonFatalExitCode)
	require.Eventually(t, func() bool {
		if runtime.GOOS != "windows" {
			_, err = net.Dial("unix", parsedCISAddr.Host+parsedCISAddr.Path)
		} else {
			if strings.HasPrefix(cisAddr, "npipe:///") {
				path := strings.TrimPrefix(cisAddr, "npipe:///")
				cisAddr = `\\.\pipe\` + path
			}
			_, err = npipe.Dial(cisAddr)("", "")
		}

		if err != nil {
			t.Logf("Connection info server is not running: %v", err)
			return false
		}

		logs := logObs.TakeAll()
		for _, l := range logs {
			t.Logf("[%s] %s", l.Level, l.Message)
			if l.Level == zapcore.WarnLevel && l.Message == expectedWarnLogMsg {
				return true
			}
		}

		return false
	}, 30*time.Second, 1*time.Second)
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
	go func() {
		err := service.Run(ctx, comm)
		require.EqualError(t, err, context.Canceled.Error())
	}()

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

func mockEndpointBinary(t *testing.T, exitCode int) string {
	// Build a mock Endpoint binary that can return a specific exit code.
	outPath := filepath.Join(t.TempDir(), "mock_endpoint")
	if runtime.GOOS == "windows" {
		outPath += ".exe"
	}

	cmd := exec.Command(
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
