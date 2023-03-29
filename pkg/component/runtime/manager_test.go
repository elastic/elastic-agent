// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//nolint:dupl // duplicate code is in test cases
package runtime

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"testing"
	"time"

	"github.com/gofrs/uuid"

	"github.com/stretchr/testify/require"
	"go.elastic.co/apm/apmtest"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/elastic/elastic-agent-libs/logp"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/configuration"
	"github.com/elastic/elastic-agent/pkg/component"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

const (
	exeExt             = ".exe"
	errActionUndefined = "action undefined"
)

var (
	fakeInputSpec = component.InputSpec{
		Name: "fake",
		Command: &component.CommandSpec{
			Timeouts: component.CommandTimeoutSpec{
				Checkin: 30 * time.Second,
				Restart: 10 * time.Millisecond, // quick restart during tests
				Stop:    30 * time.Second,
			},
		},
	}
	fakeShipperSpec = component.ShipperSpec{
		Name: "fake-shipper",
		Command: &component.CommandSpec{
			Timeouts: component.CommandTimeoutSpec{
				Checkin: 30 * time.Second,
				Restart: 10 * time.Millisecond, // quick restart during tests
				Stop:    30 * time.Second,
			},
		},
	}
)

func TestManager_SimpleComponentErr(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ai, _ := info.NewAgentInfo(true)
	m, err := NewManager(
		newDebugLogger(t),
		newDebugLogger(t),
		"localhost:0",
		ai,
		apmtest.DiscardTracer,
		newTestMonitoringMgr(),
		configuration.DefaultGRPCConfig(),
	)
	require.NoError(t, err)

	errCh := make(chan error)
	go func() {
		err := m.Run(ctx)
		if errors.Is(err, context.Canceled) {
			err = nil
		}
		errCh <- err
	}()

	waitCtx, waitCancel := context.WithTimeout(ctx, 1*time.Second)
	defer waitCancel()
	if err := m.WaitForReady(waitCtx); err != nil {
		require.NoError(t, err)
	}

	comp := component.Component{
		ID:  "error-default",
		Err: errors.New("hard-coded error"),
		Units: []component.Unit{
			{
				ID:     "error-input",
				Type:   client.UnitTypeInput,
				Config: nil,
			},
		},
	}

	subCtx, subCancel := context.WithCancel(context.Background())
	defer subCancel()
	subErrCh := make(chan error)
	go func() {
		sub := m.Subscribe(subCtx, "error-default")
		for {
			select {
			case <-subCtx.Done():
				return
			case state := <-sub.Ch():
				t.Logf("component state changed: %+v", state)
				if state.State == client.UnitStateStarting {
					// initial is starting
				} else if state.State == client.UnitStateFailed {
					unit, ok := state.Units[ComponentUnitKey{UnitType: client.UnitTypeInput, UnitID: "error-input"}]
					if ok {
						if unit.State == client.UnitStateFailed {
							// should be failed
							subErrCh <- nil
						} else {
							// unknown state that should not have occurred
							subErrCh <- fmt.Errorf("unit reported unexpected state: %v", unit.State)
						}
					}
				} else {
					subErrCh <- fmt.Errorf("component reported unexpected state: %v", state.State)
				}
			}
		}
	}()

	defer drainErrChan(errCh)
	defer drainErrChan(subErrCh)

	startTimer := time.NewTimer(100 * time.Millisecond)
	defer startTimer.Stop()
	select {
	case <-startTimer.C:
		err = m.Update([]component.Component{comp})
		require.NoError(t, err)
	case err := <-errCh:
		t.Fatalf("failed early: %s", err)
	}

	endTimer := time.NewTimer(30 * time.Second)
	defer endTimer.Stop()
LOOP:
	for {
		select {
		case <-endTimer.C:
			t.Fatalf("timed out after 30 seconds")
		case err := <-errCh:
			require.NoError(t, err)
		case err := <-subErrCh:
			require.NoError(t, err)
			break LOOP
		}
	}

	subCancel()
	cancel()

	err = <-errCh
	require.NoError(t, err)
}

func TestManager_FakeInput_StartStop(t *testing.T) {
	testPaths(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ai, _ := info.NewAgentInfo(true)
	m, err := NewManager(newDebugLogger(t), newDebugLogger(t), "localhost:0", ai, apmtest.DiscardTracer, newTestMonitoringMgr(), configuration.DefaultGRPCConfig())
	require.NoError(t, err)
	errCh := make(chan error)
	go func() {
		err := m.Run(ctx)
		if errors.Is(err, context.Canceled) {
			err = nil
		}
		errCh <- err
	}()

	waitCtx, waitCancel := context.WithTimeout(ctx, 1*time.Second)
	defer waitCancel()
	if err := m.WaitForReady(waitCtx); err != nil {
		require.NoError(t, err)
	}

	binaryPath := testBinary(t, "component")
	comp := component.Component{
		ID: "fake-default",
		InputSpec: &component.InputRuntimeSpec{
			InputType:  "fake",
			BinaryName: "",
			BinaryPath: binaryPath,
			Spec:       fakeInputSpec,
		},
		Units: []component.Unit{
			{
				ID:       "fake-input",
				Type:     client.UnitTypeInput,
				LogLevel: client.UnitLogLevelTrace,
				Config: component.MustExpectedConfig(map[string]interface{}{
					"type":    "fake",
					"state":   int(client.UnitStateHealthy),
					"message": "Fake Healthy",
				}),
			},
		},
	}

	subCtx, subCancel := context.WithCancel(context.Background())
	defer subCancel()
	subErrCh := make(chan error)
	go func() {
		sub := m.Subscribe(subCtx, "fake-default")
		for {
			select {
			case <-subCtx.Done():
				return
			case state := <-sub.Ch():
				t.Logf("component state changed: %+v", state)
				if state.State == client.UnitStateFailed {
					subErrCh <- fmt.Errorf("component failed: %s", state.Message)
				} else {
					unit, ok := state.Units[ComponentUnitKey{UnitType: client.UnitTypeInput, UnitID: "fake-input"}]
					if ok {
						if unit.State == client.UnitStateFailed {
							subErrCh <- fmt.Errorf("unit failed: %s", unit.Message)
						} else if unit.State == client.UnitStateHealthy {
							// remove the component which will stop it
							err := m.Update([]component.Component{})
							if err != nil {
								subErrCh <- err
							}
						} else if unit.State == client.UnitStateStopped {
							subErrCh <- nil
						} else if unit.State == client.UnitStateStarting {
							// acceptable
						} else {
							// unknown state that should not have occurred
							subErrCh <- fmt.Errorf("unit reported unexpected state: %v", unit.State)
						}
					} else {
						subErrCh <- errors.New("unit missing: fake-input")
					}
				}
			}
		}
	}()

	defer drainErrChan(errCh)
	defer drainErrChan(subErrCh)

	startTimer := time.NewTimer(100 * time.Millisecond)
	defer startTimer.Stop()
	select {
	case <-startTimer.C:
		err = m.Update([]component.Component{comp})
		require.NoError(t, err)
	case err := <-errCh:
		t.Fatalf("failed early: %s", err)
	}

	endTimer := time.NewTimer(30 * time.Second)
	defer endTimer.Stop()
LOOP:
	for {
		select {
		case <-endTimer.C:
			t.Fatalf("timed out after 30 seconds")
		case err := <-errCh:
			require.NoError(t, err)
		case err := <-subErrCh:
			require.NoError(t, err)
			break LOOP
		}
	}

	subCancel()
	cancel()

	err = <-errCh
	require.NoError(t, err)

	workDir := filepath.Join(paths.Run(), comp.ID)
	_, err = os.Stat(workDir)
	require.ErrorIs(t, err, os.ErrNotExist)
}

func TestManager_FakeInput_BadUnitToGood(t *testing.T) {
	testPaths(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ai, _ := info.NewAgentInfo(true)
	m, err := NewManager(newDebugLogger(t), newDebugLogger(t), "localhost:0", ai, apmtest.DiscardTracer, newTestMonitoringMgr(), configuration.DefaultGRPCConfig())
	require.NoError(t, err)
	errCh := make(chan error)
	go func() {
		err := m.Run(ctx)
		if errors.Is(err, context.Canceled) {
			err = nil
		}
		errCh <- err
	}()

	waitCtx, waitCancel := context.WithTimeout(ctx, 1*time.Second)
	defer waitCancel()
	if err := m.WaitForReady(waitCtx); err != nil {
		require.NoError(t, err)
	}

	binaryPath := testBinary(t, "component")
	comp := component.Component{
		ID: "fake-default",
		InputSpec: &component.InputRuntimeSpec{
			InputType:  "fake",
			BinaryName: "",
			BinaryPath: binaryPath,
			Spec:       fakeInputSpec,
		},
		Units: []component.Unit{
			{
				ID:       "fake-input",
				Type:     client.UnitTypeInput,
				LogLevel: client.UnitLogLevelTrace,
				Config: component.MustExpectedConfig(map[string]interface{}{
					"type":    "fake",
					"state":   int(client.UnitStateHealthy),
					"message": "Fake Healthy",
				}),
			},
			{
				ID:   "bad-input",
				Type: client.UnitTypeInput,
				Err:  errors.New("hard-error for config"),
			},
		},
	}

	subCtx, subCancel := context.WithCancel(context.Background())
	defer subCancel()
	subErrCh := make(chan error)
	go func() {
		unitBad := true

		sub := m.Subscribe(subCtx, "fake-default")
		for {
			select {
			case <-subCtx.Done():
				return
			case state := <-sub.Ch():
				t.Logf("component state changed: %+v", state)
				if state.State == client.UnitStateFailed {
					subErrCh <- fmt.Errorf("component failed: %s", state.Message)
				} else {
					unit, ok := state.Units[ComponentUnitKey{UnitType: client.UnitTypeInput, UnitID: "fake-input"}]
					if ok {
						if unit.State == client.UnitStateFailed {
							subErrCh <- fmt.Errorf("unit failed: %s", unit.Message)
						} else if unit.State == client.UnitStateHealthy {
							// update the bad unit to be good; so it will transition to healthy
							updatedComp := comp
							updatedComp.Units = make([]component.Unit, len(comp.Units))
							copy(updatedComp.Units, comp.Units)
							updatedComp.Units[1] = component.Unit{
								ID:       "bad-input",
								Type:     client.UnitTypeInput,
								LogLevel: client.UnitLogLevelTrace,
								Config: component.MustExpectedConfig(map[string]interface{}{
									"type":    "fake",
									"state":   int(client.UnitStateHealthy),
									"message": "Fake Healthy 2",
								}),
							}

							unitBad = false
							err := m.Update([]component.Component{updatedComp})
							if err != nil {
								subErrCh <- err
							}
						} else if unit.State == client.UnitStateStopped || unit.State == client.UnitStateStarting {
							// acceptable
						} else {
							// unknown state that should not have occurred
							subErrCh <- fmt.Errorf("unit reported unexpected state: %v", unit.State)
						}
					} else {
						subErrCh <- errors.New("unit missing: fake-input")
					}
					unit, ok = state.Units[ComponentUnitKey{UnitType: client.UnitTypeInput, UnitID: "bad-input"}]
					if ok {
						if unitBad {
							if unit.State != client.UnitStateFailed {
								subErrCh <- errors.New("bad-input unit should be failed")
							}
						} else {
							if unit.State == client.UnitStateFailed {
								if unit.Message == "hard-error for config" {
									// still hard-error; wait for it to go healthy
								} else {
									subErrCh <- fmt.Errorf("unit failed: %s", unit.Message)
								}
							} else if unit.State == client.UnitStateHealthy {
								// bad unit is now healthy; stop the component
								err := m.Update([]component.Component{})
								if err != nil {
									subErrCh <- err
								}
							} else if unit.State == client.UnitStateStopped {
								subErrCh <- nil
							} else if unit.State == client.UnitStateStarting {
								// acceptable
							} else {
								// unknown state that should not have occurred
								subErrCh <- fmt.Errorf("unit reported unexpected state: %v", unit.State)
							}
						}
					} else {
						subErrCh <- errors.New("unit missing: bad-input")
					}
				}
			}
		}
	}()

	defer drainErrChan(errCh)
	defer drainErrChan(subErrCh)

	startTimer := time.NewTimer(100 * time.Millisecond)
	defer startTimer.Stop()
	select {
	case <-startTimer.C:
		err = m.Update([]component.Component{comp})
		require.NoError(t, err)
	case err := <-errCh:
		t.Fatalf("failed early: %s", err)
	}

	endTimer := time.NewTimer(30 * time.Second)
	defer endTimer.Stop()
LOOP:
	for {
		select {
		case <-endTimer.C:
			t.Fatalf("timed out after 30 seconds")
		case err := <-errCh:
			require.NoError(t, err)
		case err := <-subErrCh:
			require.NoError(t, err)
			break LOOP
		}
	}

	subCancel()
	cancel()

	err = <-errCh
	require.NoError(t, err)
}

func TestManager_FakeInput_GoodUnitToBad(t *testing.T) {
	testPaths(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ai, _ := info.NewAgentInfo(true)
	m, err := NewManager(newDebugLogger(t), newDebugLogger(t), "localhost:0", ai, apmtest.DiscardTracer, newTestMonitoringMgr(), configuration.DefaultGRPCConfig())
	require.NoError(t, err)
	errCh := make(chan error)
	go func() {
		err := m.Run(ctx)
		if errors.Is(err, context.Canceled) {
			err = nil
		}
		errCh <- err
	}()

	waitCtx, waitCancel := context.WithTimeout(ctx, 1*time.Second)
	defer waitCancel()
	if err := m.WaitForReady(waitCtx); err != nil {
		require.NoError(t, err)
	}

	binaryPath := testBinary(t, "component")
	comp := component.Component{
		ID: "fake-default",
		InputSpec: &component.InputRuntimeSpec{
			InputType:  "fake",
			BinaryName: "",
			BinaryPath: binaryPath,
			Spec:       fakeInputSpec,
		},
		Units: []component.Unit{
			{
				ID:       "fake-input",
				Type:     client.UnitTypeInput,
				LogLevel: client.UnitLogLevelTrace,
				Config: component.MustExpectedConfig(map[string]interface{}{
					"type":    "fake",
					"state":   int(client.UnitStateHealthy),
					"message": "Fake Healthy",
				}),
			},
			{
				ID:       "good-input",
				Type:     client.UnitTypeInput,
				LogLevel: client.UnitLogLevelTrace,
				Config: component.MustExpectedConfig(map[string]interface{}{
					"type":    "fake",
					"state":   int(client.UnitStateHealthy),
					"message": "Fake Health 2",
				}),
			},
		},
	}

	subCtx, subCancel := context.WithCancel(context.Background())
	defer subCancel()
	subErrCh := make(chan error)
	go func() {
		unitGood := true

		sub := m.Subscribe(subCtx, "fake-default")
		for {
			select {
			case <-subCtx.Done():
				return
			case state := <-sub.Ch():
				t.Logf("component state changed: %+v", state)
				if state.State == client.UnitStateFailed {
					subErrCh <- fmt.Errorf("component failed: %s", state.Message)
				} else {
					unit, ok := state.Units[ComponentUnitKey{UnitType: client.UnitTypeInput, UnitID: "good-input"}]
					if ok {
						if unitGood {
							if unit.State == client.UnitStateFailed {
								subErrCh <- fmt.Errorf("unit failed: %s", unit.Message)
							} else if unit.State == client.UnitStateHealthy {
								// good unit it; now make it bad
								t.Logf("marking good-input as having a hard-error for config")
								updatedComp := comp
								updatedComp.Units = make([]component.Unit, len(comp.Units))
								copy(updatedComp.Units, comp.Units)
								updatedComp.Units[1] = component.Unit{
									ID:   "good-input",
									Type: client.UnitTypeInput,
									Err:  errors.New("hard-error for config"),
								}
								unitGood = false
								err := m.Update([]component.Component{updatedComp})
								if err != nil {
									subErrCh <- err
								}
							} else if unit.State == client.UnitStateStarting {
								// acceptable
							} else {
								// unknown state that should not have occurred
								subErrCh <- fmt.Errorf("unit reported unexpected state: %v", unit.State)
							}
						} else {
							if unit.State == client.UnitStateFailed {
								// went to failed; stop whole component
								err := m.Update([]component.Component{})
								if err != nil {
									subErrCh <- err
								}
							} else if unit.State == client.UnitStateStopped {
								// unit was stopped
								subErrCh <- nil
							} else {
								subErrCh <- errors.New("good-input unit should be either failed or stopped")
							}
						}
					} else {
						subErrCh <- errors.New("unit missing: good-input")
					}
				}
			}
		}
	}()

	defer drainErrChan(errCh)
	defer drainErrChan(subErrCh)

	startTimer := time.NewTimer(100 * time.Millisecond)
	defer startTimer.Stop()
	select {
	case <-startTimer.C:
		err = m.Update([]component.Component{comp})
		require.NoError(t, err)
	case err := <-errCh:
		t.Fatalf("failed early: %s", err)
	}

	endTimer := time.NewTimer(30 * time.Second)
	defer endTimer.Stop()
LOOP:
	for {
		select {
		case <-endTimer.C:
			t.Fatalf("timed out after 30 seconds")
		case err := <-errCh:
			require.NoError(t, err)
		case err := <-subErrCh:
			require.NoError(t, err)
			break LOOP
		}
	}

	subCancel()
	cancel()

	err = <-errCh
	require.NoError(t, err)
}

func TestManager_FakeInput_Configure(t *testing.T) {
	testPaths(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ai, _ := info.NewAgentInfo(true)
	m, err := NewManager(newDebugLogger(t), newDebugLogger(t), "localhost:0", ai, apmtest.DiscardTracer, newTestMonitoringMgr(), configuration.DefaultGRPCConfig())
	require.NoError(t, err)
	errCh := make(chan error)
	go func() {
		err := m.Run(ctx)
		if errors.Is(err, context.Canceled) {
			err = nil
		}
		errCh <- err
	}()

	waitCtx, waitCancel := context.WithTimeout(ctx, 1*time.Second)
	defer waitCancel()
	if err := m.WaitForReady(waitCtx); err != nil {
		require.NoError(t, err)
	}

	binaryPath := testBinary(t, "component")
	comp := component.Component{
		ID: "fake-default",
		InputSpec: &component.InputRuntimeSpec{
			InputType:  "fake",
			BinaryName: "",
			BinaryPath: binaryPath,
			Spec:       fakeInputSpec,
		},
		Units: []component.Unit{
			{
				ID:       "fake-input",
				Type:     client.UnitTypeInput,
				LogLevel: client.UnitLogLevelTrace,
				Config: component.MustExpectedConfig(map[string]interface{}{
					"type":    "fake",
					"state":   int(client.UnitStateHealthy),
					"message": "Fake Healthy",
				}),
			},
		},
	}

	subCtx, subCancel := context.WithCancel(context.Background())
	defer subCancel()
	subErrCh := make(chan error)
	go func() {
		sub := m.Subscribe(subCtx, "fake-default")
		for {
			select {
			case <-subCtx.Done():
				return
			case state := <-sub.Ch():
				t.Logf("component state changed: %+v", state)
				if state.State == client.UnitStateFailed {
					subErrCh <- fmt.Errorf("component failed: %s", state.Message)
				} else {
					unit, ok := state.Units[ComponentUnitKey{UnitType: client.UnitTypeInput, UnitID: "fake-input"}]
					if ok {
						if unit.State == client.UnitStateFailed {
							subErrCh <- fmt.Errorf("unit failed: %s", unit.Message)
						} else if unit.State == client.UnitStateHealthy {
							// update config to change the state to degraded
							comp.Units[0].Config = component.MustExpectedConfig(map[string]interface{}{
								"type":    "fake",
								"state":   int(client.UnitStateDegraded),
								"message": "Fake Degraded",
							})
							err := m.Update([]component.Component{comp})
							if err != nil {
								subErrCh <- err
							}
						} else if unit.State == client.UnitStateDegraded {
							subErrCh <- nil
						} else if unit.State == client.UnitStateStarting {
							// acceptable
						} else {
							// unknown state that should not have occurred
							subErrCh <- fmt.Errorf("unit reported unexpected state: %v", unit.State)
						}
					} else {
						subErrCh <- errors.New("unit missing: fake-input")
					}
				}
			}
		}
	}()

	defer drainErrChan(errCh)
	defer drainErrChan(subErrCh)

	startTimer := time.NewTimer(100 * time.Millisecond)
	defer startTimer.Stop()
	select {
	case <-startTimer.C:
		err = m.Update([]component.Component{comp})
		require.NoError(t, err)
	case err := <-errCh:
		t.Fatalf("failed early: %s", err)
	}

	endTimer := time.NewTimer(30 * time.Second)
	defer endTimer.Stop()
LOOP:
	for {
		select {
		case <-endTimer.C:
			t.Fatalf("timed out after 30 seconds")
		case err := <-errCh:
			require.NoError(t, err)
		case err := <-subErrCh:
			require.NoError(t, err)
			break LOOP
		}
	}

	subCancel()
	cancel()

	err = <-errCh
	require.NoError(t, err)
}

func TestManager_FakeInput_RemoveUnit(t *testing.T) {
	testPaths(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ai, _ := info.NewAgentInfo(true)
	m, err := NewManager(newDebugLogger(t), newDebugLogger(t), "localhost:0", ai, apmtest.DiscardTracer, newTestMonitoringMgr(), configuration.DefaultGRPCConfig())
	require.NoError(t, err)
	errCh := make(chan error)
	go func() {
		err := m.Run(ctx)
		if errors.Is(err, context.Canceled) {
			err = nil
		}
		errCh <- err
	}()

	waitCtx, waitCancel := context.WithTimeout(ctx, 1*time.Second)
	defer waitCancel()
	if err := m.WaitForReady(waitCtx); err != nil {
		require.NoError(t, err)
	}

	binaryPath := testBinary(t, "component")
	comp := component.Component{
		ID: "fake-default",
		InputSpec: &component.InputRuntimeSpec{
			InputType:  "fake",
			BinaryName: "",
			BinaryPath: binaryPath,
			Spec:       fakeInputSpec,
		},
		Units: []component.Unit{
			{
				ID:       "fake-input-0",
				Type:     client.UnitTypeInput,
				LogLevel: client.UnitLogLevelTrace,
				Config: component.MustExpectedConfig(map[string]interface{}{
					"type":    "fake",
					"state":   int(client.UnitStateHealthy),
					"message": "Fake Healthy 0",
				}),
			},
			{
				ID:       "fake-input-1",
				Type:     client.UnitTypeInput,
				LogLevel: client.UnitLogLevelTrace,
				Config: component.MustExpectedConfig(map[string]interface{}{
					"type":    "fake",
					"state":   int(client.UnitStateHealthy),
					"message": "Fake Healthy 1",
				}),
			},
		},
	}

	subCtx, subCancel := context.WithCancel(context.Background())
	defer subCancel()
	subErrCh := make(chan error)
	go func() {
		unit1Stopped := false

		sub := m.Subscribe(subCtx, "fake-default")
		for {
			select {
			case <-subCtx.Done():
				return
			case state := <-sub.Ch():
				t.Logf("component state changed: %+v", state)
				if state.State == client.UnitStateFailed {
					subErrCh <- fmt.Errorf("component failed: %s", state.Message)
				} else {
					unit0, ok := state.Units[ComponentUnitKey{UnitType: client.UnitTypeInput, UnitID: "fake-input-0"}]
					if ok {
						if unit0.State == client.UnitStateFailed {
							subErrCh <- fmt.Errorf("unit 0 failed: %s", unit0.Message)
						} else if unit0.State == client.UnitStateStarting || unit0.State == client.UnitStateHealthy {
							// acceptable
						} else {
							// unknown state that should not have occurred
							subErrCh <- fmt.Errorf("unit 0 reported unexpected state: %v", unit0.State)
						}
					} else {
						subErrCh <- errors.New("unit missing: fake-input-0")
					}
					unit1, ok := state.Units[ComponentUnitKey{UnitType: client.UnitTypeInput, UnitID: "fake-input-1"}]
					if ok {
						if unit1.State == client.UnitStateFailed {
							subErrCh <- fmt.Errorf("unit 1 failed: %s", unit1.Message)
						} else if unit1.State == client.UnitStateHealthy {
							// unit1 is healthy lets remove it from the component
							comp.Units = comp.Units[0:1]
							err := m.Update([]component.Component{comp})
							if err != nil {
								subErrCh <- err
							}
						} else if unit1.State == client.UnitStateStarting || unit1.State == client.UnitStateStopping {
							// acceptable
						} else if unit1.State == client.UnitStateStopped {
							// unit should have been reported stopped before being removed
							unit1Stopped = true
						} else {
							// unknown state that should not have occurred
							subErrCh <- fmt.Errorf("unit 1 reported unexpected state: %v", unit1.State)
						}
					} else {
						if len(comp.Units) == 1 {
							if unit1Stopped {
								// unit reported stopped then removed (perfect!)
								subErrCh <- nil
							} else {
								// never reported stopped
								subErrCh <- errors.New("unit 1 removed but not reported stop first")
							}
						} else {
							// should not be removed
							subErrCh <- errors.New("unit missing: fake-input-1")
						}
					}
				}
			}
		}
	}()

	defer drainErrChan(errCh)
	defer drainErrChan(subErrCh)

	startTimer := time.NewTimer(100 * time.Millisecond)
	defer startTimer.Stop()
	select {
	case <-startTimer.C:
		err = m.Update([]component.Component{comp})
		require.NoError(t, err)
	case err := <-errCh:
		t.Fatalf("failed early: %s", err)
	}

	endTimer := time.NewTimer(30 * time.Second)
	defer endTimer.Stop()
LOOP:
	for {
		select {
		case <-endTimer.C:
			t.Fatalf("timed out after 30 seconds")
		case err := <-errCh:
			require.NoError(t, err)
		case err := <-subErrCh:
			require.NoError(t, err)
			break LOOP
		}
	}

	subCancel()
	cancel()

	err = <-errCh
	require.NoError(t, err)
}

func TestManager_FakeInput_ActionState(t *testing.T) {
	testPaths(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ai, _ := info.NewAgentInfo(true)
	m, err := NewManager(newDebugLogger(t), newDebugLogger(t), "localhost:0", ai, apmtest.DiscardTracer, newTestMonitoringMgr(), configuration.DefaultGRPCConfig())
	require.NoError(t, err)
	errCh := make(chan error)
	go func() {
		err := m.Run(ctx)
		if errors.Is(err, context.Canceled) {
			err = nil
		}
		errCh <- err
	}()

	waitCtx, waitCancel := context.WithTimeout(ctx, 1*time.Second)
	defer waitCancel()
	if err := m.WaitForReady(waitCtx); err != nil {
		require.NoError(t, err)
	}

	binaryPath := testBinary(t, "component")
	comp := component.Component{
		ID: "fake-default",
		InputSpec: &component.InputRuntimeSpec{
			InputType:  "fake",
			BinaryName: "",
			BinaryPath: binaryPath,
			Spec:       fakeInputSpec,
		},
		Units: []component.Unit{
			{
				ID:       "fake-input",
				Type:     client.UnitTypeInput,
				LogLevel: client.UnitLogLevelTrace,
				Config: component.MustExpectedConfig(map[string]interface{}{
					"type":    "fake",
					"state":   int(client.UnitStateHealthy),
					"message": "Fake Healthy",
				}),
			},
		},
	}

	subCtx, subCancel := context.WithCancel(context.Background())
	defer subCancel()
	subErrCh := make(chan error)
	go func() {
		sub := m.Subscribe(subCtx, "fake-default")
		for {
			select {
			case <-subCtx.Done():
				return
			case state := <-sub.Ch():
				t.Logf("component state changed: %+v", state)
				if state.State == client.UnitStateFailed {
					subErrCh <- fmt.Errorf("component failed: %s", state.Message)
				} else {
					unit, ok := state.Units[ComponentUnitKey{UnitType: client.UnitTypeInput, UnitID: "fake-input"}]
					if ok {
						if unit.State == client.UnitStateFailed {
							subErrCh <- fmt.Errorf("unit failed: %s", unit.Message)
						} else if unit.State == client.UnitStateHealthy {
							// must be called in a separate go routine because it cannot block receiving from the
							// subscription channel
							go func() {
								actionCtx, actionCancel := context.WithTimeout(context.Background(), 15*time.Second)
								_, err := m.PerformAction(actionCtx, comp, comp.Units[0], "set_state", map[string]interface{}{
									"state":   int(client.UnitStateDegraded),
									"message": "Action Set Degraded",
								})
								actionCancel()
								if err != nil {
									subErrCh <- err
								}
							}()
						} else if unit.State == client.UnitStateDegraded {
							// action set it to degraded
							subErrCh <- nil
						} else if unit.State == client.UnitStateStarting {
							// acceptable
						} else {
							// unknown state that should not have occurred
							subErrCh <- fmt.Errorf("unit reported unexpected state: %v", unit.State)
						}
					} else {
						subErrCh <- errors.New("unit missing: fake-input")
					}
				}
			}
		}
	}()

	defer drainErrChan(errCh)
	defer drainErrChan(subErrCh)

	startTimer := time.NewTimer(100 * time.Millisecond)
	defer startTimer.Stop()
	select {
	case <-startTimer.C:
		err = m.Update([]component.Component{comp})
		require.NoError(t, err)
	case err := <-errCh:
		t.Fatalf("failed early: %s", err)
	}

	endTimer := time.NewTimer(30 * time.Second)
	defer endTimer.Stop()
LOOP:
	for {
		select {
		case <-endTimer.C:
			t.Fatalf("timed out after 30 seconds")
		case err := <-errCh:
			require.NoError(t, err)
		case err := <-subErrCh:
			require.NoError(t, err)
			break LOOP
		}
	}

	subCancel()
	cancel()

	err = <-errCh
	require.NoError(t, err)
}

func TestManager_FakeInput_Restarts(t *testing.T) {
	testPaths(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ai, _ := info.NewAgentInfo(true)
	m, err := NewManager(newDebugLogger(t), newDebugLogger(t), "localhost:0", ai, apmtest.DiscardTracer, newTestMonitoringMgr(), configuration.DefaultGRPCConfig())
	require.NoError(t, err)
	errCh := make(chan error)
	go func() {
		err := m.Run(ctx)
		if errors.Is(err, context.Canceled) {
			err = nil
		}
		errCh <- err
	}()

	waitCtx, waitCancel := context.WithTimeout(ctx, 1*time.Second)
	defer waitCancel()
	if err := m.WaitForReady(waitCtx); err != nil {
		require.NoError(t, err)
	}

	binaryPath := testBinary(t, "component")
	comp := component.Component{
		ID: "fake-default",
		InputSpec: &component.InputRuntimeSpec{
			InputType:  "fake",
			BinaryName: "",
			BinaryPath: binaryPath,
			Spec:       fakeInputSpec,
		},
		Units: []component.Unit{
			{
				ID:       "fake-input",
				Type:     client.UnitTypeInput,
				LogLevel: client.UnitLogLevelTrace,
				Config: component.MustExpectedConfig(map[string]interface{}{
					"type":    "fake",
					"state":   int(client.UnitStateHealthy),
					"message": "Fake Healthy",
				}),
			},
		},
	}

	subCtx, subCancel := context.WithCancel(context.Background())
	defer subCancel()
	subErrCh := make(chan error)
	go func() {
		killed := false

		sub := m.Subscribe(subCtx, "fake-default")
		for {
			select {
			case <-subCtx.Done():
				return
			case state := <-sub.Ch():
				t.Logf("component state changed: %+v", state)
				if state.State == client.UnitStateFailed {
					if !killed {
						subErrCh <- fmt.Errorf("component failed: %s", state.Message)
					}
				} else {
					unit, ok := state.Units[ComponentUnitKey{UnitType: client.UnitTypeInput, UnitID: "fake-input"}]
					if ok {
						if unit.State == client.UnitStateFailed {
							if !killed {
								subErrCh <- fmt.Errorf("unit failed: %s", unit.Message)
							}
						} else if unit.State == client.UnitStateHealthy {
							// force the input to exit and it should be restarted
							if !killed {
								killed = true

								t.Log("triggering kill through action")
								actionCtx, actionCancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
								_, err := m.PerformAction(actionCtx, comp, comp.Units[0], "kill", nil)
								actionCancel()
								if !errors.Is(err, context.DeadlineExceeded) {
									// should have got deadline exceeded for this call
									if err == nil {
										err = fmt.Errorf("should have got deadline exceeded")
									} else {
										err = fmt.Errorf("should have got deadline exceeded, instead got: %w", err)
									}
									subErrCh <- err
								}
							} else {
								// got back to healthy after kill
								subErrCh <- nil
							}
						} else if unit.State == client.UnitStateStarting {
							// acceptable
						} else {
							// unknown state that should not have occurred
							subErrCh <- fmt.Errorf("unit reported unexpected state: %v", unit.State)
						}
					} else {
						subErrCh <- errors.New("unit missing: fake-input")
					}
				}
			}
		}
	}()

	defer drainErrChan(errCh)
	defer drainErrChan(subErrCh)

	startTimer := time.NewTimer(100 * time.Millisecond)
	defer startTimer.Stop()
	select {
	case <-startTimer.C:
		err = m.Update([]component.Component{comp})
		require.NoError(t, err)
	case err := <-errCh:
		t.Fatalf("failed early: %s", err)
	}

	endTimer := time.NewTimer(30 * time.Second)
	defer endTimer.Stop()
LOOP:
	for {
		select {
		case <-endTimer.C:
			t.Fatalf("timed out after 30 seconds")
		case err := <-errCh:
			require.NoError(t, err)
		case err := <-subErrCh:
			require.NoError(t, err)
			break LOOP
		}
	}

	subCancel()
	cancel()

	err = <-errCh
	require.NoError(t, err)
}

func TestManager_FakeInput_Restarts_ConfigKill(t *testing.T) {
	testPaths(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ai, _ := info.NewAgentInfo(true)
	m, err := NewManager(newDebugLogger(t), newDebugLogger(t), "localhost:0", ai, apmtest.DiscardTracer, newTestMonitoringMgr(), configuration.DefaultGRPCConfig())
	require.NoError(t, err)
	errCh := make(chan error)
	go func() {
		err := m.Run(ctx)
		if errors.Is(err, context.Canceled) {
			err = nil
		}
		errCh <- err
	}()

	waitCtx, waitCancel := context.WithTimeout(ctx, 1*time.Second)
	defer waitCancel()
	if err := m.WaitForReady(waitCtx); err != nil {
		require.NoError(t, err)
	}

	// adjust input spec to allow restart
	cmdSpec := *fakeInputSpec.Command
	cmdSpec.RestartMonitoringPeriod = 1 * time.Second
	cmdSpec.MaxRestartsPerPeriod = 10
	inputSpec := fakeInputSpec
	inputSpec.Command = &cmdSpec

	binaryPath := testBinary(t, "component")
	comp := component.Component{
		ID: "fake-default",
		InputSpec: &component.InputRuntimeSpec{
			InputType:  "fake",
			BinaryName: "",
			BinaryPath: binaryPath,
			Spec:       inputSpec,
		},
		Units: []component.Unit{
			{
				ID:       "fake-input",
				Type:     client.UnitTypeInput,
				LogLevel: client.UnitLogLevelTrace,
				Config: component.MustExpectedConfig(map[string]interface{}{
					"type":    "fake",
					"state":   int(client.UnitStateHealthy),
					"message": "Fake Healthy",
				}),
			},
		},
	}

	subCtx, subCancel := context.WithCancel(context.Background())
	defer subCancel()
	subErrCh := make(chan error)
	go func() {
		killed := false

		sub := m.Subscribe(subCtx, "fake-default")
		for {
			select {
			case <-subCtx.Done():
				return
			case state := <-sub.Ch():
				t.Logf("component state changed: %+v", state)
				if state.State == client.UnitStateFailed {
					if !killed {
						subErrCh <- fmt.Errorf("component failed: %s", state.Message)
					}
				} else {
					unit, ok := state.Units[ComponentUnitKey{UnitType: client.UnitTypeInput, UnitID: "fake-input"}]
					if ok {
						if unit.State == client.UnitStateFailed {
							if !killed {
								subErrCh <- fmt.Errorf("unit failed: %s", unit.Message)
							}
						} else if unit.State == client.UnitStateHealthy {
							// force the input to exit and it should be restarted
							if !killed {
								killed = true

								r := regexp.MustCompile(`pid \'(?P<pid>\d+)\'`)
								rp := r.FindStringSubmatch(state.Message)
								t.Logf("triggering kill through config on pid %s", rp)
								comp.Units[0].Config = component.MustExpectedConfig(map[string]interface{}{
									"type":    "fake",
									"state":   int(client.UnitStateHealthy),
									"message": "Fake Healthy",
									"kill":    rp[1],
								})
								err := m.Update([]component.Component{comp})
								if err != nil {
									subErrCh <- err
								}
							} else {
								// got back to healthy after kill
								subErrCh <- nil
							}
						} else if unit.State == client.UnitStateStarting || unit.State == client.UnitStateStopped {
							// acceptable
						} else {
							// unknown state that should not have occurred
							subErrCh <- fmt.Errorf("unit reported unexpected state: %v", unit.State)
						}
					} else {
						subErrCh <- errors.New("unit missing: fake-input")
					}
				}
			}
		}
	}()

	defer drainErrChan(errCh)
	defer drainErrChan(subErrCh)

	startTimer := time.NewTimer(100 * time.Millisecond)
	defer startTimer.Stop()
	select {
	case <-startTimer.C:
		err = m.Update([]component.Component{comp})
		require.NoError(t, err)
	case err := <-errCh:
		t.Fatalf("failed early: %s", err)
	}

	endTimer := time.NewTimer(1 * time.Minute)
	defer endTimer.Stop()
LOOP:
	for {
		select {
		case <-endTimer.C:
			t.Fatalf("timed out after 1 minute")
		case err := <-errCh:
			require.NoError(t, err)
		case err := <-subErrCh:
			require.NoError(t, err)
			break LOOP
		}
	}

	subCancel()
	cancel()

	err = <-errCh
	require.NoError(t, err)
}

func TestManager_FakeInput_KeepsRestarting(t *testing.T) {
	testPaths(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ai, _ := info.NewAgentInfo(true)
	m, err := NewManager(newDebugLogger(t), newDebugLogger(t), "localhost:0", ai, apmtest.DiscardTracer, newTestMonitoringMgr(), configuration.DefaultGRPCConfig())
	require.NoError(t, err)
	errCh := make(chan error)
	go func() {
		err := m.Run(ctx)
		if errors.Is(err, context.Canceled) {
			err = nil
		}
		errCh <- err
	}()

	waitCtx, waitCancel := context.WithTimeout(ctx, 1*time.Second)
	defer waitCancel()
	if err := m.WaitForReady(waitCtx); err != nil {
		require.NoError(t, err)
	}

	// adjust input spec to allow restart
	cmdSpec := *fakeInputSpec.Command
	cmdSpec.RestartMonitoringPeriod = 1 * time.Second
	cmdSpec.MaxRestartsPerPeriod = 10
	inputSpec := fakeInputSpec
	inputSpec.Command = &cmdSpec

	binaryPath := testBinary(t, "component")
	comp := component.Component{
		ID: "fake-default",
		InputSpec: &component.InputRuntimeSpec{
			InputType:  "fake",
			BinaryName: "",
			BinaryPath: binaryPath,
			Spec:       inputSpec,
		},
		Units: []component.Unit{
			{
				ID:       "fake-input",
				Type:     client.UnitTypeInput,
				LogLevel: client.UnitLogLevelTrace,
				Config: component.MustExpectedConfig(map[string]interface{}{
					"type":             "fake",
					"state":            int(client.UnitStateHealthy),
					"message":          "Fake Healthy",
					"kill_on_interval": true,
				}),
			},
		},
	}

	subCtx, subCancel := context.WithCancel(context.Background())
	defer subCancel()
	subErrCh := make(chan error)
	go func() {
		lastStoppedCount := 0
		stoppedCount := 0

		sub := m.Subscribe(subCtx, "fake-default")
		for {
			select {
			case <-subCtx.Done():
				return
			case state := <-sub.Ch():
				t.Logf("component state changed: %+v", state)
				if state.State == client.UnitStateFailed {
					// should not go failed because we allow restart per period
					subErrCh <- fmt.Errorf("component failed: %s", state.Message)
				} else {
					unit, ok := state.Units[ComponentUnitKey{UnitType: client.UnitTypeInput, UnitID: "fake-input"}]
					if ok {
						if unit.State == client.UnitStateFailed {
							// unit should not be failed because we allow restart per period
							subErrCh <- fmt.Errorf("unit failed: %s", unit.Message)
						} else if unit.State == client.UnitStateHealthy {
							if lastStoppedCount != stoppedCount {
								lastStoppedCount = stoppedCount

								// send new config on each healthy report
								comp.Units[0].Config = component.MustExpectedConfig(map[string]interface{}{
									"type":             "fake",
									"state":            int(client.UnitStateHealthy),
									"message":          fmt.Sprintf("Fake Healthy %d", lastStoppedCount),
									"kill_on_interval": true,
								})
								err := m.Update([]component.Component{comp})
								if err != nil {
									subErrCh <- err
								}
							}
							if stoppedCount >= 3 {
								// got stopped 3 times and got back to healthy
								subErrCh <- nil
							}
						} else if unit.State == client.UnitStateStarting {
							// acceptable
						} else if unit.State == client.UnitStateStopped {
							stoppedCount += 1
						} else {
							// unknown state that should not have occurred
							subErrCh <- fmt.Errorf("unit reported unexpected state: %v", unit.State)
						}
					} else {
						subErrCh <- errors.New("unit missing: fake-input")
					}
				}
			}
		}
	}()

	defer drainErrChan(errCh)
	defer drainErrChan(subErrCh)

	startTimer := time.NewTimer(100 * time.Millisecond)
	defer startTimer.Stop()
	select {
	case <-startTimer.C:
		err = m.Update([]component.Component{comp})
		require.NoError(t, err)
	case err := <-errCh:
		t.Fatalf("failed early: %s", err)
	}

	endTimer := time.NewTimer(1 * time.Minute)
	defer endTimer.Stop()
LOOP:
	for {
		select {
		case <-endTimer.C:
			t.Fatalf("timed out after 1 minute")
		case err := <-errCh:
			require.NoError(t, err)
		case err := <-subErrCh:
			require.NoError(t, err)
			break LOOP
		}
	}

	subCancel()
	cancel()

	err = <-errCh
	require.NoError(t, err)
}

func TestManager_FakeInput_RestartsOnMissedCheckins(t *testing.T) {
	testPaths(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ai, _ := info.NewAgentInfo(true)
	m, err := NewManager(newDebugLogger(t), newDebugLogger(t), "localhost:0", ai, apmtest.DiscardTracer, newTestMonitoringMgr(), configuration.DefaultGRPCConfig())
	require.NoError(t, err)
	errCh := make(chan error)
	go func() {
		err := m.Run(ctx)
		if errors.Is(err, context.Canceled) {
			err = nil
		}
		errCh <- err
	}()

	waitCtx, waitCancel := context.WithTimeout(ctx, 1*time.Second)
	defer waitCancel()
	if err := m.WaitForReady(waitCtx); err != nil {
		require.NoError(t, err)
	}

	binaryPath := testBinary(t, "component")
	comp := component.Component{
		ID: "fake-default",
		InputSpec: &component.InputRuntimeSpec{
			InputType:  "fake",
			BinaryName: "",
			BinaryPath: binaryPath,
			Spec: component.InputSpec{
				Name: "fake",
				Command: &component.CommandSpec{
					Timeouts: component.CommandTimeoutSpec{
						// very low checkin timeout so we can cause missed check-ins
						Checkin: 100 * time.Millisecond,
						Stop:    30 * time.Second,
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

	subCtx, subCancel := context.WithCancel(context.Background())
	defer subCancel()
	subErrCh := make(chan error)
	go func() {
		wasDegraded := false

		sub := m.Subscribe(subCtx, "fake-default")
		for {
			select {
			case <-subCtx.Done():
				return
			case state := <-sub.Ch():
				t.Logf("component state changed: %+v", state)
				if state.State == client.UnitStateStarting || state.State == client.UnitStateHealthy {
					// starting and healthy are allowed
				} else if state.State == client.UnitStateDegraded {
					// should go to degraded first
					wasDegraded = true
				} else if state.State == client.UnitStateFailed {
					if wasDegraded {
						subErrCh <- nil
					} else {
						subErrCh <- errors.New("should have been degraded before failed")
					}
				} else {
					subErrCh <- fmt.Errorf("unknown component state: %v", state.State)
				}
			}
		}
	}()

	defer drainErrChan(errCh)
	defer drainErrChan(subErrCh)

	startTimer := time.NewTimer(100 * time.Millisecond)
	defer startTimer.Stop()
	select {
	case <-startTimer.C:
		err = m.Update([]component.Component{comp})
		require.NoError(t, err)
	case err := <-errCh:
		t.Fatalf("failed early: %s", err)
	}

	endTimer := time.NewTimer(30 * time.Second)
	defer endTimer.Stop()
LOOP:
	for {
		select {
		case <-endTimer.C:
			t.Fatalf("timed out after 30 seconds")
		case err := <-errCh:
			require.NoError(t, err)
		case err := <-subErrCh:
			require.NoError(t, err)
			break LOOP
		}
	}

	subCancel()
	cancel()

	err = <-errCh
	require.NoError(t, err)
}

func TestManager_FakeInput_InvalidAction(t *testing.T) {
	testPaths(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ai, _ := info.NewAgentInfo(true)
	m, err := NewManager(newDebugLogger(t), newDebugLogger(t), "localhost:0", ai, apmtest.DiscardTracer, newTestMonitoringMgr(), configuration.DefaultGRPCConfig())
	require.NoError(t, err)
	errCh := make(chan error)
	go func() {
		err := m.Run(ctx)
		if errors.Is(err, context.Canceled) {
			err = nil
		}
		errCh <- err
	}()

	waitCtx, waitCancel := context.WithTimeout(ctx, 1*time.Second)
	defer waitCancel()
	if err := m.WaitForReady(waitCtx); err != nil {
		require.NoError(t, err)
	}

	binaryPath := testBinary(t, "component")
	comp := component.Component{
		ID: "fake-default",
		InputSpec: &component.InputRuntimeSpec{
			InputType:  "fake",
			BinaryName: "",
			BinaryPath: binaryPath,
			Spec:       fakeInputSpec,
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

	subCtx, subCancel := context.WithCancel(context.Background())
	defer subCancel()
	subErrCh := make(chan error)
	go func() {
		sub := m.Subscribe(subCtx, "fake-default")
		for {
			select {
			case <-subCtx.Done():
				return
			case state := <-sub.Ch():
				t.Logf("component state changed: %+v", state)
				if state.State == client.UnitStateFailed {
					subErrCh <- fmt.Errorf("component failed: %s", state.Message)
				} else {
					unit, ok := state.Units[ComponentUnitKey{UnitType: client.UnitTypeInput, UnitID: "fake-input"}]
					if ok {
						if unit.State == client.UnitStateFailed {
							subErrCh <- fmt.Errorf("unit failed: %s", unit.Message)
						} else if unit.State == client.UnitStateHealthy {
							actionCtx, actionCancel := context.WithTimeout(context.Background(), 5*time.Second)
							_, err := m.PerformAction(actionCtx, comp, comp.Units[0], "invalid_missing_action", nil)
							actionCancel()
							if err == nil {
								subErrCh <- fmt.Errorf("should have returned an error")
							} else if err.Error() != errActionUndefined {
								subErrCh <- fmt.Errorf("should have returned error: action undefined")
							} else {
								subErrCh <- nil
							}
						} else if unit.State == client.UnitStateStarting {
							// acceptable
						} else {
							// unknown state that should not have occurred
							subErrCh <- fmt.Errorf("unit reported unexpected state: %v", unit.State)
						}
					} else {
						subErrCh <- errors.New("unit missing: fake-input")
					}
				}
			}
		}
	}()

	defer drainErrChan(errCh)
	defer drainErrChan(subErrCh)

	startTimer := time.NewTimer(100 * time.Millisecond)
	defer startTimer.Stop()
	select {
	case <-startTimer.C:
		err = m.Update([]component.Component{comp})
		require.NoError(t, err)
	case err := <-errCh:
		t.Fatalf("failed early: %s", err)
	}

	endTimer := time.NewTimer(30 * time.Second)
	defer endTimer.Stop()
LOOP:
	for {
		select {
		case <-endTimer.C:
			t.Fatalf("timed out after 30 seconds")
		case err := <-errCh:
			require.NoError(t, err)
		case err := <-subErrCh:
			require.NoError(t, err)
			break LOOP
		}
	}

	subCancel()
	cancel()

	err = <-errCh
	require.NoError(t, err)
}

func TestManager_FakeInput_MultiComponent(t *testing.T) {
	testPaths(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ai, _ := info.NewAgentInfo(true)
	m, err := NewManager(newDebugLogger(t), newDebugLogger(t), "localhost:0", ai, apmtest.DiscardTracer, newTestMonitoringMgr(), configuration.DefaultGRPCConfig())
	require.NoError(t, err)
	errCh := make(chan error)
	go func() {
		err := m.Run(ctx)
		if errors.Is(err, context.Canceled) {
			err = nil
		}
		errCh <- err
	}()

	waitCtx, waitCancel := context.WithTimeout(ctx, 1*time.Second)
	defer waitCancel()
	if err := m.WaitForReady(waitCtx); err != nil {
		require.NoError(t, err)
	}

	binaryPath := testBinary(t, "component")
	runtimeSpec := component.InputRuntimeSpec{
		InputType:  "fake",
		BinaryName: "",
		BinaryPath: binaryPath,
		Spec:       fakeInputSpec,
	}
	components := []component.Component{
		{
			ID:        "fake-0",
			InputSpec: &runtimeSpec,
			Units: []component.Unit{
				{
					ID:   "fake-input-0-0",
					Type: client.UnitTypeInput,
					Config: component.MustExpectedConfig(map[string]interface{}{
						"type":    "fake",
						"state":   int(client.UnitStateHealthy),
						"message": "Fake Healthy 0-0",
					}),
				},
				{
					ID:   "fake-input-0-1",
					Type: client.UnitTypeInput,
					Config: component.MustExpectedConfig(map[string]interface{}{
						"type":    "fake",
						"state":   int(client.UnitStateHealthy),
						"message": "Fake Healthy 0-1",
					}),
				},
				{
					ID:   "fake-input-0-2",
					Type: client.UnitTypeInput,
					Config: component.MustExpectedConfig(map[string]interface{}{
						"type":    "fake",
						"state":   int(client.UnitStateHealthy),
						"message": "Fake Healthy 0-2",
					}),
				},
			},
		},
		{
			ID:        "fake-1",
			InputSpec: &runtimeSpec,
			Units: []component.Unit{
				{
					ID:   "fake-input-1-0",
					Type: client.UnitTypeInput,
					Config: component.MustExpectedConfig(map[string]interface{}{
						"type":    "fake",
						"state":   int(client.UnitStateHealthy),
						"message": "Fake Healthy 1-0",
					}),
				},
				{
					ID:   "fake-input-1-1",
					Type: client.UnitTypeInput,
					Config: component.MustExpectedConfig(map[string]interface{}{
						"type":    "fake",
						"state":   int(client.UnitStateHealthy),
						"message": "Fake Healthy 1-1",
					}),
				},
				{
					ID:   "fake-input-1-2",
					Type: client.UnitTypeInput,
					Config: component.MustExpectedConfig(map[string]interface{}{
						"type":    "fake",
						"state":   int(client.UnitStateHealthy),
						"message": "Fake Healthy 1-2",
					}),
				},
			},
		},
		{
			ID:        "fake-2",
			InputSpec: &runtimeSpec,
			Units: []component.Unit{
				{
					ID:   "fake-input-2-0",
					Type: client.UnitTypeInput,
					Config: component.MustExpectedConfig(map[string]interface{}{
						"type":    "fake",
						"state":   int(client.UnitStateHealthy),
						"message": "Fake Healthy 2-0",
					}),
				},
				{
					ID:   "fake-input-2-1",
					Type: client.UnitTypeInput,
					Config: component.MustExpectedConfig(map[string]interface{}{
						"type":    "fake",
						"state":   int(client.UnitStateHealthy),
						"message": "Fake Healthy 2-1",
					}),
				},
				{
					ID:   "fake-input-2-2",
					Type: client.UnitTypeInput,
					Config: component.MustExpectedConfig(map[string]interface{}{
						"type":    "fake",
						"state":   int(client.UnitStateHealthy),
						"message": "Fake Healthy 2-2",
					}),
				},
			},
		},
	}

	subCtx, subCancel := context.WithCancel(context.Background())
	defer subCancel()
	subErrCh0 := make(chan error)
	subErrCh1 := make(chan error)
	subErrCh2 := make(chan error)
	go func() {
		sub0 := m.Subscribe(subCtx, "fake-0")
		sub1 := m.Subscribe(subCtx, "fake-1")
		sub2 := m.Subscribe(subCtx, "fake-2")
		for {
			select {
			case <-subCtx.Done():
				return
			case state := <-sub0.Ch():
				t.Logf("component fake-0 state changed: %+v", state)
				signalState(subErrCh0, &state, []client.UnitState{client.UnitStateHealthy})
			case state := <-sub1.Ch():
				t.Logf("component fake-1 state changed: %+v", state)
				signalState(subErrCh1, &state, []client.UnitState{client.UnitStateHealthy})
			case state := <-sub2.Ch():
				t.Logf("component fake-2 state changed: %+v", state)
				signalState(subErrCh2, &state, []client.UnitState{client.UnitStateHealthy})
			}
		}
	}()

	defer drainErrChan(errCh)
	defer drainErrChan(subErrCh0)
	defer drainErrChan(subErrCh1)
	defer drainErrChan(subErrCh2)

	startTimer := time.NewTimer(100 * time.Millisecond)
	defer startTimer.Stop()
	select {
	case <-startTimer.C:
		err = m.Update(components)
		require.NoError(t, err)
	case err := <-errCh:
		t.Fatalf("failed early: %s", err)
	}

	count := 0
	endTimer := time.NewTimer(30 * time.Second)
	defer endTimer.Stop()
LOOP:
	for {
		select {
		case <-endTimer.C:
			t.Fatalf("timed out after 30 seconds")
		case err := <-errCh:
			require.NoError(t, err)
		case err := <-subErrCh0:
			require.NoError(t, err)
			count++
			if count >= 3 {
				break LOOP
			}
		case err := <-subErrCh1:
			require.NoError(t, err)
			count++
			if count >= 3 {
				break LOOP
			}
		case err := <-subErrCh2:
			require.NoError(t, err)
			count++
			if count >= 3 {
				break LOOP
			}
		}
	}

	subCancel()
	cancel()

	err = <-errCh
	require.NoError(t, err)
}

func TestManager_FakeInput_LogLevel(t *testing.T) {
	testPaths(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ai, _ := info.NewAgentInfo(true)
	m, err := NewManager(newDebugLogger(t), newDebugLogger(t), "localhost:0", ai, apmtest.DiscardTracer, newTestMonitoringMgr(), configuration.DefaultGRPCConfig())
	require.NoError(t, err)
	errCh := make(chan error)
	go func() {
		err := m.Run(ctx)
		if errors.Is(err, context.Canceled) {
			err = nil
		}
		errCh <- err
	}()

	waitCtx, waitCancel := context.WithTimeout(ctx, 1*time.Second)
	defer waitCancel()
	if err := m.WaitForReady(waitCtx); err != nil {
		require.NoError(t, err)
	}

	binaryPath := testBinary(t, "component")
	comp := component.Component{
		ID: "fake-default",
		InputSpec: &component.InputRuntimeSpec{
			InputType:  "fake",
			BinaryName: "",
			BinaryPath: binaryPath,
			Spec:       fakeInputSpec,
		},
		Units: []component.Unit{
			{
				ID:       "fake-input",
				Type:     client.UnitTypeInput,
				LogLevel: client.UnitLogLevelInfo,
				Config: component.MustExpectedConfig(map[string]interface{}{
					"type":    "fake",
					"state":   int(client.UnitStateHealthy),
					"message": "Fake Healthy",
				}),
			},
		},
	}

	subCtx, subCancel := context.WithCancel(context.Background())
	defer subCancel()
	subErrCh := make(chan error)
	go func() {
		sub := m.Subscribe(subCtx, "fake-default")
		for {
			select {
			case <-subCtx.Done():
				return
			case state := <-sub.Ch():
				t.Logf("component state changed: %+v", state)
				if state.State == client.UnitStateFailed {
					subErrCh <- fmt.Errorf("component failed: %s", state.Message)
				} else {
					unit, ok := state.Units[ComponentUnitKey{UnitType: client.UnitTypeInput, UnitID: "fake-input"}]
					if ok {
						if unit.State == client.UnitStateFailed {
							subErrCh <- fmt.Errorf("unit failed: %s", unit.Message)
						} else if unit.State == client.UnitStateHealthy {
							updatedComp := comp
							updatedComp.Units = make([]component.Unit, len(comp.Units))
							copy(updatedComp.Units, comp.Units)
							updatedComp.Units[0] = component.Unit{
								ID:       "fake-input",
								Type:     client.UnitTypeInput,
								LogLevel: client.UnitLogLevelTrace,
								Config: component.MustExpectedConfig(map[string]interface{}{
									"type":    "fake",
									"state":   int(client.UnitStateHealthy),
									"message": "Fake Healthy",
								}),
							}

							actionCtx, actionCancel := context.WithTimeout(context.Background(), 5*time.Second)
							_, err := m.PerformAction(actionCtx, comp, comp.Units[0], "invalid_missing_action", nil)
							actionCancel()
							if err == nil {
								subErrCh <- fmt.Errorf("should have returned an error")
							} else if err.Error() != errActionUndefined {
								subErrCh <- fmt.Errorf("should have returned error: action undefined")
							} else {
								subErrCh <- nil
							}
						} else if unit.State == client.UnitStateStarting {
							// acceptable
						} else {
							// unknown state that should not have occurred
							subErrCh <- fmt.Errorf("unit reported unexpected state: %v", unit.State)
						}
					} else {
						subErrCh <- errors.New("unit missing: fake-input")
					}
				}
			}
		}
	}()

	defer drainErrChan(errCh)
	defer drainErrChan(subErrCh)

	startTimer := time.NewTimer(100 * time.Millisecond)
	defer startTimer.Stop()
	select {
	case <-startTimer.C:
		err = m.Update([]component.Component{comp})
		require.NoError(t, err)
	case err := <-errCh:
		t.Fatalf("failed early: %s", err)
	}

	endTimer := time.NewTimer(30 * time.Second)
	defer endTimer.Stop()
LOOP:
	for {
		select {
		case <-endTimer.C:
			t.Fatalf("timed out after 30 seconds")
		case err := <-errCh:
			require.NoError(t, err)
		case err := <-subErrCh:
			require.NoError(t, err)
			break LOOP
		}
	}

	subCancel()
	cancel()

	err = <-errCh
	require.NoError(t, err)
}

func TestManager_FakeShipper(t *testing.T) {
	/*
		This test runs one instance of the fake/component and an instance of the fake/shipper. They get connected
		together, and it ensures that a test event is sent between each instance. Below is a breakdown on how this
		test performs this work and ensures that an event is sent between the two instances.

		1. Wait for the shipper input (GRPC server) is healthy.
		2. Wait for the component output (GRPC client) is healthy.
		3. Create a unique ID to use for the event ID.
		4. Send `record_event` action to the shipper input (GRPC server); won't return until it actually gets the event.
		5. Send `send_event` action to the component fake input (GRPC client); returns once sent.
		6. Wait for `record_event` action to return from the shipper input (GRPC server).
	*/
	t.Skip("Flaky test: https://github.com/elastic/elastic-agent/issues/2301")

	testPaths(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ai, _ := info.NewAgentInfo(true)
	m, err := NewManager(newDebugLogger(t), newDebugLogger(t), "localhost:0", ai, apmtest.DiscardTracer, newTestMonitoringMgr(), configuration.DefaultGRPCConfig())
	require.NoError(t, err)
	errCh := make(chan error)
	go func() {
		err := m.Run(ctx)
		if errors.Is(err, context.Canceled) {
			err = nil
		}
		errCh <- err
	}()

	waitCtx, waitCancel := context.WithTimeout(ctx, 1*time.Second)
	defer waitCancel()
	if err := m.WaitForReady(waitCtx); err != nil {
		require.NoError(t, err)
	}

	componentPath := testBinary(t, "component")
	shipperPath := testBinary(t, "shipper")
	comps := []component.Component{
		{
			ID: "fake-default",
			InputSpec: &component.InputRuntimeSpec{
				InputType:  "fake",
				BinaryName: "",
				BinaryPath: componentPath,
				Spec:       fakeInputSpec,
			},
			Units: []component.Unit{
				{
					ID:       "fake-input",
					Type:     client.UnitTypeInput,
					LogLevel: client.UnitLogLevelTrace,
					Config: component.MustExpectedConfig(map[string]interface{}{
						"type":    "fake",
						"state":   int(client.UnitStateHealthy),
						"message": "Fake Healthy",
					}),
				},
				{
					ID:       "fake-default",
					Type:     client.UnitTypeOutput,
					LogLevel: client.UnitLogLevelTrace,
					Config: component.MustExpectedConfig(map[string]interface{}{
						"type": "fake-shipper",
					}),
				},
			},
			Shipper: &component.ShipperReference{
				ComponentID: "fake-shipper-default",
				UnitID:      "fake-default",
			},
		},
		{
			ID: "fake-shipper-default",
			ShipperSpec: &component.ShipperRuntimeSpec{
				ShipperType: "fake-shipper",
				BinaryName:  "",
				BinaryPath:  shipperPath,
				Spec:        fakeShipperSpec,
			},
			Units: []component.Unit{
				{
					ID:       "fake-default",
					Type:     client.UnitTypeInput,
					LogLevel: client.UnitLogLevelTrace,
					Config: component.MustExpectedConfig(map[string]interface{}{
						"id":   "fake-default",
						"type": "fake-shipper",
						"units": []interface{}{
							map[string]interface{}{
								"id": "fake-input",
								"config": map[string]interface{}{
									"type":    "fake",
									"state":   int(client.UnitStateHealthy),
									"message": "Fake Healthy",
								},
							},
						},
					}),
				},
				{
					ID:       "fake-default",
					Type:     client.UnitTypeOutput,
					LogLevel: client.UnitLogLevelTrace,
					Config: component.MustExpectedConfig(map[string]interface{}{
						"type": "fake-action-output",
					}),
				},
			},
		},
	}

	subCtx, subCancel := context.WithCancel(context.Background())
	defer subCancel()
	subErrCh := make(chan error)
	go func() {
		shipperOn := false
		compConnected := false

		sendEvent := func() (bool, error) {
			if !shipperOn || !compConnected {
				// wait until connected
				return false, nil
			}

			// send an event between component and the fake shipper
			eventID, err := uuid.NewV4()
			if err != nil {
				return true, err
			}

			// wait for the event on the shipper side
			gotEvt := make(chan error)
			go func() {
				actionCtx, actionCancel := context.WithTimeout(context.Background(), 30*time.Second)
				_, err := m.PerformAction(actionCtx, comps[1], comps[1].Units[1], "record_event", map[string]interface{}{
					"id": eventID.String(),
				})
				actionCancel()
				gotEvt <- err
			}()

			// send the fake event
			actionCtx, actionCancel := context.WithTimeout(context.Background(), 15*time.Second)
			_, err = m.PerformAction(actionCtx, comps[0], comps[0].Units[0], "send_event", map[string]interface{}{
				"id": eventID.String(),
			})
			actionCancel()
			if err != nil {
				return true, err
			}

			err = <-gotEvt
			if err == nil {
				t.Logf("successfully sent event from fake input to fake shipper, event ID: %s", eventID.String())
			}
			return true, err
		}

		shipperSub := m.Subscribe(subCtx, "fake-shipper-default")
		compSub := m.Subscribe(subCtx, "fake-default")
		for {
			select {
			case <-subCtx.Done():
				return
			case state := <-shipperSub.Ch():
				t.Logf("shipper state changed: %+v", state)
				if state.State == client.UnitStateFailed {
					subErrCh <- fmt.Errorf("shipper failed: %s", state.Message)
				} else {
					unit, ok := state.Units[ComponentUnitKey{UnitType: client.UnitTypeInput, UnitID: "fake-default"}]
					if ok {
						if unit.State == client.UnitStateFailed {
							subErrCh <- fmt.Errorf("unit failed: %s", unit.Message)
						} else if unit.State == client.UnitStateHealthy {
							shipperOn = true
							ok, err := sendEvent()
							if ok {
								if err != nil {
									subErrCh <- err
								} else {
									// successful; turn it all off
									err := m.Update([]component.Component{})
									if err != nil {
										subErrCh <- err
									}
								}
							}
						} else if unit.State == client.UnitStateStopped {
							subErrCh <- nil
						} else if unit.State == client.UnitStateStarting {
							// acceptable
						} else {
							// unknown state that should not have occurred
							subErrCh <- fmt.Errorf("unit reported unexpected state: %v", unit.State)
						}
					} else {
						subErrCh <- errors.New("unit missing: fake-input")
					}
				}
			case state := <-compSub.Ch():
				t.Logf("component state changed: %+v", state)
				if state.State == client.UnitStateFailed {
					subErrCh <- fmt.Errorf("component failed: %s", state.Message)
				} else {
					unit, ok := state.Units[ComponentUnitKey{UnitType: client.UnitTypeOutput, UnitID: "fake-default"}]
					if ok {
						if unit.State == client.UnitStateFailed {
							subErrCh <- fmt.Errorf("unit failed: %s", unit.Message)
						} else if unit.State == client.UnitStateHealthy {
							compConnected = true
							ok, err := sendEvent()
							if ok {
								if err != nil {
									subErrCh <- err
								} else {
									// successful; turn it all off
									err := m.Update([]component.Component{})
									if err != nil {
										subErrCh <- err
									}
								}
							}
						} else if unit.State == client.UnitStateStopped {
							subErrCh <- nil
						} else if unit.State == client.UnitStateStarting || unit.State == client.UnitStateConfiguring {
							// acceptable
						} else {
							// unknown state that should not have occurred
							subErrCh <- fmt.Errorf("unit reported unexpected state: %v", unit.State)
						}
					} else {
						subErrCh <- errors.New("unit missing: fake-input")
					}
				}
			}
		}
	}()

	defer drainErrChan(errCh)
	defer drainErrChan(subErrCh)

	startTimer := time.NewTimer(100 * time.Millisecond)
	defer startTimer.Stop()
	select {
	case <-startTimer.C:
		err = m.Update(comps)
		require.NoError(t, err)
	case err := <-errCh:
		t.Fatalf("failed early: %s", err)
	}

	endTimer := time.NewTimer(2 * time.Minute)
	defer endTimer.Stop()
LOOP:
	for {
		select {
		case <-endTimer.C:
			t.Fatalf("timed out after 2 minutes")
		case err := <-errCh:
			require.NoError(t, err)
		case err := <-subErrCh:
			require.NoError(t, err)
			break LOOP
		}
	}

	subCancel()
	cancel()

	err = <-errCh
	require.NoError(t, err)
}

func TestManager_FakeInput_OutputChange(t *testing.T) {
	t.Skip("Flaky test: https://github.com/elastic/elastic-agent/issues/2403")
	testPaths(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ai, _ := info.NewAgentInfo(true)
	m, err := NewManager(newDebugLogger(t), newDebugLogger(t), "localhost:0", ai, apmtest.DiscardTracer, newTestMonitoringMgr(), configuration.DefaultGRPCConfig())
	require.NoError(t, err)
	errCh := make(chan error)
	go func() {
		err := m.Run(ctx)
		if errors.Is(err, context.Canceled) {
			err = nil
		}
		errCh <- err
	}()

	waitCtx, waitCancel := context.WithTimeout(ctx, 1*time.Second)
	defer waitCancel()
	if err := m.WaitForReady(waitCtx); err != nil {
		require.NoError(t, err)
	}

	binaryPath := testBinary(t, "component")
	runtimeSpec := component.InputRuntimeSpec{
		InputType:  "fake",
		BinaryName: "",
		BinaryPath: binaryPath,
		Spec:       fakeInputSpec,
	}
	components := []component.Component{
		{
			ID:        "fake-0",
			InputSpec: &runtimeSpec,
			Units: []component.Unit{
				{
					ID:   "fake-input-0-0",
					Type: client.UnitTypeInput,
					Config: component.MustExpectedConfig(map[string]interface{}{
						"type":    "fake",
						"state":   int(client.UnitStateHealthy),
						"message": "Fake Healthy 0-0",
					}),
				},
				{
					ID:   "fake-input-0-1",
					Type: client.UnitTypeInput,
					Config: component.MustExpectedConfig(map[string]interface{}{
						"type":    "fake",
						"state":   int(client.UnitStateHealthy),
						"message": "Fake Healthy 0-1",
					}),
				},
				{
					ID:   "fake-input-0-2",
					Type: client.UnitTypeInput,
					Config: component.MustExpectedConfig(map[string]interface{}{
						"type":    "fake",
						"state":   int(client.UnitStateHealthy),
						"message": "Fake Healthy 0-1",
					}),
				},
			},
		},
	}

	components2 := []component.Component{
		{
			ID:        "fake-1",
			InputSpec: &runtimeSpec,
			Units: []component.Unit{
				{
					ID:   "fake-input-1-0",
					Type: client.UnitTypeInput,
					Config: component.MustExpectedConfig(map[string]interface{}{
						"type":    "fake",
						"state":   int(client.UnitStateHealthy),
						"message": "Fake Healthy 0-0",
					}),
				},
				{
					ID:   "fake-input-1-1",
					Type: client.UnitTypeInput,
					Config: component.MustExpectedConfig(map[string]interface{}{
						"type":    "fake",
						"state":   int(client.UnitStateHealthy),
						"message": "Fake Healthy 0-1",
					}),
				},
				{
					ID:   "fake-input-1-1",
					Type: client.UnitTypeInput,
					Config: component.MustExpectedConfig(map[string]interface{}{
						"type":    "fake",
						"state":   int(client.UnitStateHealthy),
						"message": "Fake Healthy 0-1",
					}),
				},
			},
		},
	}

	type progressionStep struct {
		componentID string
		state       ComponentState
	}
	stateProgression := make([]progressionStep, 0)

	subCtx, subCancel := context.WithCancel(context.Background())
	defer subCancel()
	stateProgCh := make(chan progressionStep)
	subErrCh0 := make(chan error)
	subErrCh1 := make(chan error)
	go func() {
		sub0 := m.Subscribe(subCtx, "fake-0")
		sub1 := m.Subscribe(subCtx, "fake-1")
		for {
			select {
			case <-subCtx.Done():
				close(stateProgCh)
				return
			case state := <-sub0.Ch():
				t.Logf("component fake-0 state changed: %+v", state)
				signalState(subErrCh0, &state, []client.UnitState{client.UnitStateHealthy, client.UnitStateStopped})
				stateProgCh <- progressionStep{"fake-o", state}
			case state := <-sub1.Ch():
				t.Logf("component fake-1 state changed: %+v", state)
				signalState(subErrCh1, &state, []client.UnitState{client.UnitStateHealthy})
				stateProgCh <- progressionStep{"fake-o", state}
			}
		}
	}()

	go func() {
		for step := range stateProgCh {
			stateProgression = append(stateProgression, step)
		}
	}()

	defer drainErrChan(errCh)
	defer drainErrChan(subErrCh0)
	defer drainErrChan(subErrCh1)

	startTimer := time.NewTimer(100 * time.Millisecond)
	defer startTimer.Stop()
	select {
	case <-startTimer.C:
		err = m.Update(components)
		require.NoError(t, err)
	case err := <-errCh:
		t.Fatalf("failed early: %s", err)
	}

	updateTimeout := 300 * time.Millisecond
	if runtime.GOOS == component.Windows {
		// windows is slow, preventing flakyness
		updateTimeout = 550 * time.Millisecond
	}
	updateTimer := time.NewTimer(updateTimeout)
	defer updateTimer.Stop()
	select {
	case <-updateTimer.C:
		err = m.Update(components2)
		require.NoError(t, err)
	case err := <-errCh:
		t.Fatalf("failed early: %s", err)
	}

	count := 0
	endTimer := time.NewTimer(30 * time.Second)
	defer endTimer.Stop()
LOOP:
	for {
		select {
		case <-endTimer.C:
			t.Fatalf("timed out after 30 seconds")
		case err := <-errCh:
			require.NoError(t, err)
		case err := <-subErrCh0:
			require.NoError(t, err)
			count++
			if count >= 2 {
				break LOOP
			}
		case err := <-subErrCh1:
			require.NoError(t, err)
			count++
			if count >= 2 {
				break LOOP
			}
		}
	}

	subCancel()
	cancel()

	// check progresstion, require stop fake-0 before start fake-1
	wasStopped := false
	for _, step := range stateProgression {
		if step.componentID == "fake-0" && step.state.State == client.UnitStateStopped {
			wasStopped = true
		}
		if step.componentID == "fake-1" && step.state.State == client.UnitStateStarting {
			require.True(t, wasStopped)
			break
		}
	}

	err = <-errCh
	require.NoError(t, err)
}

func newDebugLogger(t *testing.T) *logger.Logger {
	t.Helper()

	loggerCfg := logger.DefaultLoggingConfig()
	loggerCfg.Level = logp.DebugLevel
	loggerCfg.ToStderr = true

	log, err := logger.NewFromConfig("", loggerCfg, false)
	require.NoError(t, err)
	return log
}

func drainErrChan(ch chan error) {
	for {
		select {
		case <-ch:
		default:
			return
		}
	}
}

func signalState(subErrCh chan error, state *ComponentState, acceptableStates []client.UnitState) {
	if state.State == client.UnitStateFailed {
		subErrCh <- fmt.Errorf("component failed: %s", state.Message)
	} else {
		issue := ""
		healthy := 0
		for key, unit := range state.Units {
			if unit.State == client.UnitStateStarting {
				// acceptable
			} else if isAcceptableState(unit.State, acceptableStates) {
				healthy++
			} else if issue == "" {
				issue = fmt.Sprintf("unit %s in invalid state %v", key.UnitID, unit.State)
			}
		}
		if issue != "" {
			subErrCh <- fmt.Errorf("%s", issue)
		}
		if healthy == 3 {
			subErrCh <- nil
		}
	}
}

func isAcceptableState(state client.UnitState, acceptableStates []client.UnitState) bool {
	for _, s := range acceptableStates {
		if s == state {
			return true
		}
	}
	return false
}

func testPaths(t *testing.T) {
	t.Helper()

	versioned := paths.IsVersionHome()
	topPath := paths.Top()

	tmpDir, err := os.MkdirTemp("", "at-*")
	if err != nil {
		t.Fatalf("failed to create temp directory: %s", err)
	}
	paths.SetVersionHome(false)
	paths.SetTop(tmpDir)

	t.Cleanup(func() {
		paths.SetVersionHome(versioned)
		paths.SetTop(topPath)
		_ = os.RemoveAll(tmpDir)
	})
}

func testBinary(t *testing.T, name string) string {
	t.Helper()

	var err error
	binaryPath := filepath.Join("..", "fake", name, name)
	binaryPath, err = filepath.Abs(binaryPath)
	if err != nil {
		t.Fatalf("failed abs %s: %s", binaryPath, err)
	}
	if runtime.GOOS == component.Windows {
		binaryPath += exeExt
	} else {
		err = os.Chown(binaryPath, os.Geteuid(), os.Getgid())
		if err != nil {
			t.Fatalf("failed chown %s: %s", binaryPath, err)
		}
		err = os.Chmod(binaryPath, 0755)
		if err != nil {
			t.Fatalf("failed chmod %s: %s", binaryPath, err)
		}
	}
	return binaryPath
}

type testMonitoringManager struct{}

func newTestMonitoringMgr() *testMonitoringManager { return &testMonitoringManager{} }

func (*testMonitoringManager) EnrichArgs(_ string, _ string, args []string) []string { return args }
func (*testMonitoringManager) Prepare(_ string) error                                { return nil }
func (*testMonitoringManager) Cleanup(string) error                                  { return nil }
