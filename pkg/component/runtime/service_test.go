// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package runtime

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/kardianos/service"
	"golang.org/x/sync/errgroup"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/elastic-agent/pkg/component"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

func TestServiceStart(t *testing.T) {
	// Skipping this test, since it requires proper endpoint service binaries. Leaving the test in because it is useful for local interractive testing with Endpoint service
	t.Skip()
	log := logp.NewLogger("test_service")
	comp := component.Component{
		Spec: component.InputRuntimeSpec{
			// BinaryName: "endpoint-security.exe",
			// BinaryPath: `C:\work\elastic-agent-8.5.0-SNAPSHOT-windows-x86_64\data\elastic-agent-b6521b\components\endpoint-security.exe`,
			BinaryName: "endpoint-security",
			//BinaryPath: "/home/amaus/elastic/elastic-agent/build/distributions/elastic-agent-8.5.0-SNAPSHOT-linux-x86_64/data/elastic-agent-b6521b/components/endpoint-security",
			BinaryPath: "/Users/amaus/elastic/elastic-agent/build/distributions/elastic-agent-8.5.0-SNAPSHOT-darwin-x86_64/data/elastic-agent-2099aa/components/endpoint-security",
			Spec: component.InputSpec{
				Service: &component.ServiceSpec{
					// Name:  "ElasticEndpoint",
					Name: "co.elastic.endpoint",
					Operations: component.ServiceOperationsSpec{
						Check: &component.ServiceOperationsCommandSpec{
							Args: []string{"verify", "--log", "stderr"}, Env: []component.CommandEnvSpec(nil), Timeout: 30000000000,
						},
						Install: &component.ServiceOperationsCommandSpec{
							Args: []string{"install", "--log", "stderr", "--upgrade", "--resources", "endpoint-security-resources.zip"}, Env: []component.CommandEnvSpec(nil), Timeout: 600000000000,
						},
						Uninstall: &component.ServiceOperationsCommandSpec{
							Args: []string{"uninstall", "--log", "stderr"}, Env: []component.CommandEnvSpec(nil), Timeout: 600000000000,
						},
					},
				},
			},
		},
	}

	service, err := NewServiceRuntime(comp, log)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cn := context.WithCancel(context.Background())
	defer cn()

	g, ctx := errgroup.WithContext(ctx)

	comm := newMockCommunicator()

	// Run main loop
	g.Go(func() error {
		return service.Run(ctx, comm)
	})

	//err = service.Start()
	err = service.Stop()
	//err = service.Teardown()
	if err != nil {
		t.Fatal(err)
	}

	g.Go(func() error {
		for {
			select {
			case state := <-service.Watch():
				//nolint:forbidigo // leave it here, not a real unit test, but super useful code for development
				fmt.Printf("Got State: %#v\n", state)
				switch state.State {
				case client.UnitStateHealthy, client.UnitStateStopped:
					cn()
					return nil
				}
			case <-ctx.Done():
				return nil
			}
		}
	})

	err = g.Wait()
	if err != nil {
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	}
}

type mockServiceCall int

const (
	serviceStartCall mockServiceCall = iota
	serviceStopCall
)

type mockService struct {
	name string

	emitStatuses    []service.Status
	emitStatusIndex int
	keepLastStatus  bool

	serviceCalls []mockServiceCall
}

func (s *mockService) Run() error {
	return nil
}

// Start signals to the OS service manager the given service should start.
func (s *mockService) Start() error {
	s.serviceCalls = append(s.serviceCalls, serviceStartCall)
	return nil
}

// Stop signals to the OS service manager the given service should stop.
func (s *mockService) Stop() error {
	s.serviceCalls = append(s.serviceCalls, serviceStopCall)
	return nil
}

// Restart signals to the OS service manager the given service should stop then start.
func (s *mockService) Restart() error {
	return nil
}

// Install setups up the given service in the OS service manager. This may require
// greater rights. Will return an error if it is already installed.
func (s *mockService) Install() error {
	return nil
}

// Uninstall removes the given service from the OS service manager. This may require
// greater rights. Will return an error if the service is not present.
func (s *mockService) Uninstall() error {
	return nil
}

// Opens and returns a system logger. If the user program is running
// interactively rather then as a service, the returned logger will write to
// os.Stderr. If errs is non-nil errors will be sent on errs as well as
// returned from Logger's functions.
func (s *mockService) Logger(errs chan<- error) (service.Logger, error) {
	return nil, nil
}

// SystemLogger opens and returns a system logger. If errs is non-nil errors
// will be sent on errs as well as returned from Logger's functions.
func (s *mockService) SystemLogger(errs chan<- error) (service.Logger, error) {
	return nil, nil
}

// String displays the name of the service. The display name if present,
// otherwise the name.
func (s *mockService) String() string {
	return s.name
}

// Platform displays the name of the system that manages the service.
// In most cases this will be the same as service.Platform().
func (s *mockService) Platform() string {
	return service.Platform()
}

// Status returns the current service status.
func (s *mockService) Status() (service.Status, error) {
	if len(s.emitStatuses) > 0 {
		if s.emitStatusIndex > len(s.emitStatuses)-1 {
			if s.keepLastStatus {
				return s.emitStatuses[len(s.emitStatuses)-1], nil
			}
			return service.StatusUnknown, fmt.Errorf("unexpected Status() call, was called more times than expected: %d", len(s.emitStatuses))
		}
		status := s.emitStatuses[s.emitStatusIndex]
		s.emitStatusIndex++
		return status, nil
	}
	return service.StatusUnknown, nil
}

type mockPlatformServiceRecorder struct {
	svc *mockService
}

func newMockPlatformServiceRecorder(emitStatuses []service.Status, keepLastStatus bool) *mockPlatformServiceRecorder {
	return &mockPlatformServiceRecorder{
		svc: &mockService{
			emitStatuses:   emitStatuses,
			keepLastStatus: keepLastStatus,
		},
	}
}
func (m *mockPlatformServiceRecorder) platformServiceFunc(name string) (service.Service, error) {
	m.svc.name = name
	return m.svc, nil
}

type executeServiceCommandEntry struct {
	BinaryPath string
	Spec       *component.ServiceOperationsCommandSpec
}

type executeServiceCommandRecorder struct {
	responses map[string]error // mocked responses for the commands where the key is the command key in this case the first param "verify", "install", "uninstall"
	commands  []executeServiceCommandEntry
}

func (e *executeServiceCommandRecorder) ExecuteServiceCommand(ctx context.Context, log *logger.Logger, binaryPath string, spec *component.ServiceOperationsCommandSpec) error {
	e.commands = append(e.commands, executeServiceCommandEntry{binaryPath, spec})

	command := spec.Args[0]
	if len(e.responses) > 0 {
		if err, ok := e.responses[command]; ok {
			return err
		}
	}

	return nil
}

const testBinaryPath = "/Users/amaus/elastic/elastic-agent/build/distributions/elastic-agent-8.5.0-SNAPSHOT-darwin-x86_64/data/elastic-agent-2099aa/components/endpoint-security"

var (
	checkSpec = &component.ServiceOperationsCommandSpec{
		Args: []string{"verify", "--log", "stderr"}, Env: []component.CommandEnvSpec(nil), Timeout: 30000000000,
	}

	installSpec = &component.ServiceOperationsCommandSpec{
		Args: []string{"install", "--log", "stderr", "--upgrade", "--resources", "endpoint-security-resources.zip"}, Env: []component.CommandEnvSpec(nil), Timeout: 600000000000,
	}

	uninstallSpec = &component.ServiceOperationsCommandSpec{
		Args: []string{"uninstall", "--log", "stderr"}, Env: []component.CommandEnvSpec(nil), Timeout: 600000000000,
	}
)

func TestPlatformServiceStart(t *testing.T) {
	log := logp.NewLogger("test_service")

	comp := component.Component{
		Spec: component.InputRuntimeSpec{
			BinaryName: "endpoint-security",
			BinaryPath: testBinaryPath,
			Spec: component.InputSpec{
				Service: &component.ServiceSpec{
					Name: "co.elastic.endpoint",
					Timeouts: component.ServiceTimeoutSpec{
						Checkin: 100 * time.Millisecond, // Fast checkin interval for mocks in order to run the tests faster
					},
					Operations: component.ServiceOperationsSpec{
						Check:     checkSpec,
						Install:   installSpec,
						Uninstall: uninstallSpec,
					},
				},
			},
		},
		Units: []component.Unit{
			{
				ID:   "fake-input",
				Type: client.UnitTypeInput,
				Config: component.MustExpectedConfig(map[string]interface{}{
					"type":    "fake",
					"state":   int(client.UnitStateHealthy),
					"message": "Fake Healthy",
				}),
			},
		},
	}

	tests := []struct {
		name string

		// mocks behavours
		executeServiceCommandResponses map[string]error
		emitServiceStatuses            []service.Status
		keepLastStatus                 bool

		// expected result behavours
		expectedCommandsExecuted []executeServiceCommandEntry

		// expected states
		expectedStates []client.UnitState

		// expected calls to the
		serviceCalls []mockServiceCall

		// final state
		finalState client.UnitState

		// sendUnit
		sendUnitStates []client.UnitState
	}{
		{
			name:                           "service is not installed, successful install",
			executeServiceCommandResponses: map[string]error{checkSpec.Args[0]: errors.New("service is not installed")},
			emitServiceStatuses:            []service.Status{service.StatusStopped, service.StatusRunning},
			expectedCommandsExecuted:       []executeServiceCommandEntry{{testBinaryPath, checkSpec}, {testBinaryPath, installSpec}},
			expectedStates:                 []client.UnitState{client.UnitStateStarting, client.UnitStateHealthy},
			finalState:                     client.UnitStateHealthy,
			sendUnitStates:                 []client.UnitState{client.UnitStateHealthy},
			serviceCalls:                   []mockServiceCall{serviceStartCall},
		},
		{
			name: "service is not installed, failed install",
			executeServiceCommandResponses: map[string]error{
				checkSpec.Args[0]:   errors.New("service is not installed"),
				installSpec.Args[0]: errors.New("service install failed"),
			},
			emitServiceStatuses:      []service.Status{service.StatusStopped, service.StatusRunning},
			expectedCommandsExecuted: []executeServiceCommandEntry{{testBinaryPath, checkSpec}, {testBinaryPath, installSpec}},
			expectedStates:           []client.UnitState{client.UnitStateStarting, client.UnitStateFailed},
			finalState:               client.UnitStateFailed,
		},
		{
			name:                     "service is installed, not running",
			emitServiceStatuses:      []service.Status{service.StatusStopped, service.StatusRunning},
			expectedCommandsExecuted: []executeServiceCommandEntry{{testBinaryPath, checkSpec}},
			expectedStates:           []client.UnitState{client.UnitStateStarting, client.UnitStateHealthy},
			finalState:               client.UnitStateHealthy,
			sendUnitStates:           []client.UnitState{client.UnitStateHealthy},
			serviceCalls:             []mockServiceCall{serviceStartCall},
		},
		{
			name:                     "service is installed, already running",
			emitServiceStatuses:      []service.Status{service.StatusRunning},
			expectedCommandsExecuted: []executeServiceCommandEntry{{testBinaryPath, checkSpec}},
			expectedStates:           []client.UnitState{client.UnitStateStarting, client.UnitStateHealthy},
			sendUnitStates:           []client.UnitState{client.UnitStateHealthy},
			finalState:               client.UnitStateHealthy,
			serviceCalls:             []mockServiceCall{serviceStartCall},
		},
		{
			name:                     "service is installed, running, no checkins",
			emitServiceStatuses:      []service.Status{service.StatusRunning},
			keepLastStatus:           true,
			expectedCommandsExecuted: []executeServiceCommandEntry{{testBinaryPath, checkSpec}},
			expectedStates:           []client.UnitState{client.UnitStateStarting, client.UnitStateHealthy, client.UnitStateDegraded, client.UnitStateDegraded, client.UnitStateFailed},
			sendUnitStates:           []client.UnitState{client.UnitStateHealthy},
			finalState:               client.UnitStateFailed,
			serviceCalls:             []mockServiceCall{serviceStartCall},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			svc, err := NewServiceRuntime(comp, log)
			if err != nil {
				t.Fatal(err)
			}

			// Inject mocks
			serviceRecorder := newMockPlatformServiceRecorder(tc.emitServiceStatuses, tc.keepLastStatus)
			svc.(*ServiceRuntime).platformServiceImpl = serviceRecorder.platformServiceFunc
			commandRecorder := &executeServiceCommandRecorder{responses: tc.executeServiceCommandResponses}
			svc.(*ServiceRuntime).executeServiceCommandImpl = commandRecorder.ExecuteServiceCommand

			ctx, cn := context.WithCancel(context.Background())
			defer cn()

			comm := newMockCommunicator()

			// Run main loop
			g, ctx := errgroup.WithContext(ctx)
			g.Go(func() error {
				err := svc.Run(ctx, comm)
				if errors.Is(err, context.Canceled) {
					return nil
				}
				return err
			})

			err = svc.Start()
			if err != nil {
				t.Fatal(err)
			}

			for _, us := range tc.sendUnitStates {
				us := us
				go comm.sendCheckingObserved(us, comp.Units)
			}

			var recordedStates []client.UnitState
		LOOP:
			for {
				state := <-svc.Watch()
				recordedStates = append(recordedStates, state.State)
				if tc.finalState == state.State {
					cn()
					break LOOP
				}
			}

			err = g.Wait()
			if err != nil {
				t.Fatal(err)
			}

			diff := cmp.Diff(tc.expectedStates, recordedStates)
			if diff != "" {
				t.Error(diff)
			}

			diff = cmp.Diff(tc.serviceCalls, serviceRecorder.svc.serviceCalls)
			if diff != "" {
				t.Error(diff)
			}

			diff = cmp.Diff(tc.expectedCommandsExecuted, commandRecorder.commands)
			if diff != "" {
				t.Error(diff)
			}

		})
	}
}
