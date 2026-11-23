// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package coordinator

// This is a companion to coordinator_test.go focusing on the new
// deterministic / channel-based testing model. Over time more of the old
// tests should migrate to this model, and when that progresses far enough
// the two files should be merged, the separation is just to informally
// keep track of migration progress.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths/pathstest"

	"github.com/elastic/elastic-agent-client/v7/pkg/proto"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/ttl"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi/acker"
	"github.com/elastic/elastic-agent/internal/pkg/testutils"

	"github.com/open-telemetry/opentelemetry-collector-contrib/pkg/status"
	"go.opentelemetry.io/collector/component/componentstatus"
	"go.opentelemetry.io/collector/confmap"
	"gopkg.in/yaml.v3"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/elastic/beats/v7/pkg/logp"
	"github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/cpulimit"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/monitoring/reload"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/reexec"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/secret"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact"
	upgradeErrors "github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact/download/errors"
	"github.com/elastic/elastic-agent/internal/pkg/agent/configuration"
	"github.com/elastic/elastic-agent/internal/pkg/agent/storage"
	"github.com/elastic/elastic-agent/internal/pkg/agent/transpiler"
	"github.com/elastic/elastic-agent/internal/pkg/agent/vault"
	"github.com/elastic/elastic-agent/internal/pkg/composable"
	"github.com/elastic/elastic-agent/internal/pkg/composable/providers/localdynamic"
	"github.com/elastic/elastic-agent/internal/pkg/config"
	monitoringCfg "github.com/elastic/elastic-agent/internal/pkg/core/monitoring/config"
	"github.com/elastic/elastic-agent/pkg/backoff"
	pkgcomponent "github.com/elastic/elastic-agent/pkg/component"
	"github.com/elastic/elastic-agent/pkg/component/runtime"
	agentclient "github.com/elastic/elastic-agent/pkg/control/v2/client"
	"github.com/elastic/elastic-agent/pkg/core/logger"
	"github.com/elastic/elastic-agent/pkg/core/logger/loggertest"
	"github.com/elastic/elastic-agent/pkg/features"
	"github.com/elastic/elastic-agent/pkg/fleetapi"
	"github.com/elastic/elastic-agent/pkg/limits"
	"github.com/elastic/elastic-agent/pkg/upgrade/details"
	"github.com/elastic/elastic-agent/pkg/utils/broadcaster"
)

var testSecretMarkerFunc = func(*logger.Logger, *config.Config) error {
	// no-op secret marker function for testing
	return nil
}

func TestMain(m *testing.M) {
	// Register the local_dynamic provider so composable.IsDynamic can find it.
	// In the actual application this is done by internal/pkg/composable/include.
	composable.Providers.MustAddDynamicProvider("local_dynamic", localdynamic.DynamicProviderBuilder)
	os.Exit(m.Run())
}

func TestVarsManagerError(t *testing.T) {
	// Set a one-second timeout -- nothing here should block, but if it
	// does let's report a failure instead of timing out the test runner.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	// Channels have buffer length 1 so we don't have to run on multiple
	// goroutines.
	stateChan := make(chan State, 1)
	varsErrorChan := make(chan error, 1)
	coord := &Coordinator{
		state: State{
			CoordinatorState:   agentclient.Healthy,
			CoordinatorMessage: "Running",
		},
		stateBroadcaster: &broadcaster.Broadcaster[State]{
			InputChan: stateChan,
		},
		managerChans: managerChans{
			varsManagerError: varsErrorChan,
		},
		componentPIDTicker: time.NewTicker(time.Second * 30),
	}
	// Send an error via the vars manager channel, and let Coordinator update
	const errorStr = "force error"
	varsErrorChan <- errors.New(errorStr)
	coord.runLoopIteration(ctx)

	// Make sure the new state reflects the error
	select {
	case state := <-stateChan:
		assert.Equal(t, agentclient.Failed, state.State, "expected Failed State")
		assert.Contains(t, state.Message, "Vars manager:", "state message should report the error as coming from the Vars manager")
		assert.Contains(t, state.Message, errorStr, "state message should contain the error that was sent")
	default:
		assert.Fail(t, "Coordinator's state didn't change")
	}

	// Clear the error and let Coordinator update
	varsErrorChan <- nil
	coord.runLoopIteration(ctx)

	// Make sure the state has returned to its original value
	select {
	case state := <-stateChan:
		assert.Equal(t, agentclient.Healthy, state.State, "expected Healthy State")
		assert.Equal(t, "Running", state.Message, "state message should return to its original value")
	default:
		assert.Fail(t, "Coordinator's state didn't change")
	}
}

func TestCoordinatorReportsUnhealthyComponents(t *testing.T) {
	// Set a one-second timeout -- nothing here should block, but if it
	// does let's report a failure instead of timing out the test runner.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	// Channels have buffer length 1 so we don't have to run on multiple
	// goroutines.
	stateChan := make(chan State, 1)
	runtimeChan := make(chan runtime.ComponentComponentState, 1)
	coord := &Coordinator{
		state: State{
			CoordinatorState:   agentclient.Healthy,
			CoordinatorMessage: "Running",
		},
		stateBroadcaster: &broadcaster.Broadcaster[State]{
			InputChan: stateChan,
		},
		managerChans: managerChans{
			runtimeManagerUpdate: runtimeChan,
		},
		componentPIDTicker: time.NewTicker(time.Second * 30),
	}

	unhealthyComponent := runtime.ComponentComponentState{
		Component: pkgcomponent.Component{ID: "test-component-1"},
		State: runtime.ComponentState{
			State:   client.UnitStateDegraded,
			Message: "test message",
		},
	}
	// Send the component state to the Coordinator channel and let it run for an
	// iteration to update
	runtimeChan <- unhealthyComponent
	coord.runLoopIteration(ctx)
	select {
	case state := <-stateChan:
		assert.Equal(t, agentclient.Degraded, state.State, "Degraded component state should cause degraded Coordinator state")
		assert.Equal(t, "1 or more components/units in a degraded state", state.Message, "state message should reflect degraded component")
	default:
		assert.Fail(t, "Coordinator's state didn't change")
	}

	// Try again, escalating the component's state to Failed.
	// The state message should change slightly, but the overall Coordinator
	// state should still just be Degraded -- components / units can't cause
	// a Failed state, only errors in the managers can do that.
	unhealthyComponent.State.State = client.UnitStateFailed
	runtimeChan <- unhealthyComponent
	coord.runLoopIteration(ctx)
	select {
	case state := <-stateChan:
		assert.Equal(t, agentclient.Degraded, state.State, "Failed component state should cause degraded Coordinator state")
		assert.Equal(t, "1 or more components/units in a failed state", state.Message, "state message should reflect failed component")
	default:
		assert.Fail(t, "Coordinator's state didn't change")
	}

	// Reset component state to UnitStateStarting and verify the
	// Coordinator recovers
	unhealthyComponent.State.State = client.UnitStateStarting
	runtimeChan <- unhealthyComponent
	coord.runLoopIteration(ctx)
	select {
	case state := <-stateChan:
		assert.Equal(t, agentclient.Healthy, state.State, "Starting component state should cause healthy Coordinator state")
		assert.Equal(t, "Running", state.Message, "Healthy coordinator should return to baseline state message")
	default:
		assert.Fail(t, "Coordinator's state didn't change")
	}
}

func TestCoordinatorReportsUnhealthyOTelComponents(t *testing.T) {
	// Set a one-second timeout -- nothing here should block, but if it
	// does let's report a failure instead of timing out the test runner.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	// Channels have buffer length 1 so we don't have to run on multiple
	// goroutines.
	stateChan := make(chan State, 1)
	otelChan := make(chan *status.AggregateStatus, 1)
	coord := &Coordinator{
		state: State{
			CoordinatorState:   agentclient.Healthy,
			CoordinatorMessage: "Running",
		},
		stateBroadcaster: &broadcaster.Broadcaster[State]{
			InputChan: stateChan,
		},
		managerChans: managerChans{
			otelManagerCollectorUpdate: otelChan,
		},
		componentPIDTicker: time.NewTicker(time.Second * 30),
	}

	unhealthyOTel := &status.AggregateStatus{
		Event: componentstatus.NewEvent(componentstatus.StatusRecoverableError),
		ComponentStatusMap: map[string]*status.AggregateStatus{
			"test-component-1": {
				Event: componentstatus.NewRecoverableErrorEvent(errors.New("test message")),
			},
		},
	}

	// Send the otel component state to the Coordinator channel and let it run for an
	// iteration to update
	otelChan <- unhealthyOTel
	coord.runLoopIteration(ctx)
	select {
	case state := <-stateChan:
		assert.Equal(t, agentclient.Degraded, state.State, "Degraded component state should cause degraded Coordinator state")
		assert.Equal(t, "1 or more components/units in a degraded state", state.Message, "state message should reflect degraded component")
	default:
		assert.Fail(t, "Coordinator's state didn't change")
	}

	// Try again, escalating the component's state to Failed.
	// The state message should change slightly, but the overall Coordinator
	// state should still just be Degraded -- components / units can't cause
	// a Failed state, only errors in the managers can do that.
	unhealthyOTel = &status.AggregateStatus{
		Event: componentstatus.NewEvent(componentstatus.StatusFatalError),
		ComponentStatusMap: map[string]*status.AggregateStatus{
			"test-component-1": {
				Event: componentstatus.NewFatalErrorEvent(errors.New("test message")),
			},
		},
	}
	otelChan <- unhealthyOTel
	coord.runLoopIteration(ctx)
	select {
	case state := <-stateChan:
		assert.Equal(t, agentclient.Degraded, state.State, "Failed component state should cause degraded Coordinator state")
		assert.Equal(t, "1 or more components/units in a failed state", state.Message, "state message should reflect failed component")
	default:
		assert.Fail(t, "Coordinator's state didn't change")
	}

	// Reset component state to UnitStateStarting and verify the
	// Coordinator recovers
	unhealthyOTel = &status.AggregateStatus{
		Event: componentstatus.NewEvent(componentstatus.StatusStarting),
		ComponentStatusMap: map[string]*status.AggregateStatus{
			"test-component-1": {
				Event: componentstatus.NewEvent(componentstatus.StatusStarting),
			},
		},
	}
	otelChan <- unhealthyOTel
	coord.runLoopIteration(ctx)
	select {
	case state := <-stateChan:
		assert.Equal(t, agentclient.Healthy, state.State, "Starting component state should cause healthy Coordinator state")
		assert.Equal(t, "Running", state.Message, "Healthy coordinator should return to baseline state message")
	default:
		assert.Fail(t, "Coordinator's state didn't change")
	}
}

func TestCoordinatorComponentStatesAreSeparate(t *testing.T) {
	// Report two healthy components, set one to unhealthy, then verify that
	// healthy state reports from the second component don't restore the
	// Coordinator state until the first one is healthy again too.

	// Set a one-second timeout -- nothing here should block, but if it
	// does let's report a failure instead of timing out the test runner.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	// Channels have buffer length 1 so we don't have to run on multiple
	// goroutines.
	runtimeChan := make(chan runtime.ComponentComponentState, 1)
	initialState := State{
		CoordinatorState:   agentclient.Healthy,
		CoordinatorMessage: "Running",
	}
	coord := &Coordinator{
		state: initialState,
		// We want a synchronous broadcaster with no i/o buffers -- we are making
		// multiple calls at once and we only want the most recent state after
		// the final call.
		stateBroadcaster: broadcaster.New(initialState, 0, 0),
		managerChans: managerChans{
			runtimeManagerUpdate: runtimeChan,
		},
		componentPIDTicker: time.NewTicker(time.Second * 30),
	}

	comp1 := runtime.ComponentComponentState{
		Component: pkgcomponent.Component{ID: "test-component-1"},
		State: runtime.ComponentState{
			State:   client.UnitStateStarting,
			Message: "test message",
		},
	}
	comp2 := runtime.ComponentComponentState{
		Component: pkgcomponent.Component{ID: "test-component-2"},
		State: runtime.ComponentState{
			State:   client.UnitStateStarting,
			Message: "test message",
		},
	}

	// Send the component states to the Coordinator channel and let it update
	runtimeChan <- comp1
	coord.runLoopIteration(ctx)
	runtimeChan <- comp2
	coord.runLoopIteration(ctx)

	state := coord.State()
	assert.Equal(t, agentclient.Healthy, state.State, "Starting components should produce healthy Coordinator")
	assert.Equal(t, "Running", state.Message, "Starting components shouldn't affect state message")

	// Set comp2 to failed, but send a healthy comp1 state again, and
	// verify that Coordinator is still Degraded.
	comp2.State.State = client.UnitStateFailed
	runtimeChan <- comp2
	coord.runLoopIteration(ctx)
	runtimeChan <- comp1
	coord.runLoopIteration(ctx)

	state = coord.State()

	assert.Equal(t, agentclient.Degraded, state.State, "Failed component state should cause degraded Coordinator state")
	assert.Equal(t, "1 or more components/units in a failed state", state.Message, "state message should reflect failed component")

	// Make comp2 healthy again and verify that Coordinator recovers
	comp2.State.State = client.UnitStateHealthy
	runtimeChan <- comp2
	coord.runLoopIteration(ctx)
	state = coord.State()
	assert.Equal(t, agentclient.Healthy, state.State, "Starting component state should cause healthy Coordinator state")
	assert.Equal(t, "Running", state.Message, "Healthy coordinator should return to baseline state message")
}

func TestCoordinatorReportsUnhealthyUnits(t *testing.T) {
	// Set a one-second timeout -- nothing here should block, but if it
	// does let's report a failure instead of timing out the test runner.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	// Channels have buffer length 1 so we don't have to run on multiple
	// goroutines.
	stateChan := make(chan State, 1)
	runtimeChan := make(chan runtime.ComponentComponentState, 1)
	coord := &Coordinator{
		state: State{
			CoordinatorState:   agentclient.Healthy,
			CoordinatorMessage: "Running",
		},
		stateBroadcaster: &broadcaster.Broadcaster[State]{
			InputChan: stateChan,
		},
		managerChans: managerChans{
			runtimeManagerUpdate: runtimeChan,
		},
		componentPIDTicker: time.NewTicker(time.Second * 30),
	}

	// Create a healthy component with healthy input and output units
	inputKey := runtime.ComponentUnitKey{
		UnitType: client.UnitTypeInput,
		UnitID:   "input-unit-1"}
	outputKey := runtime.ComponentUnitKey{
		UnitType: client.UnitTypeOutput,
		UnitID:   "output-unit-1"}
	comp := runtime.ComponentComponentState{
		Component: pkgcomponent.Component{ID: "test-component-1"},
		State: runtime.ComponentState{
			State:   client.UnitStateHealthy,
			Message: "everything is fine",
			Units: map[runtime.ComponentUnitKey]runtime.ComponentUnitState{
				inputKey: {
					State:   client.UnitStateHealthy,
					Message: "everything is fine",
				},
				outputKey: {
					State:   client.UnitStateHealthy,
					Message: "everything is fine",
				},
			},
		},
	}
	// Send the component state to the Coordinator and verify it is healthy
	runtimeChan <- comp
	coord.runLoopIteration(ctx)
	select {
	case state := <-stateChan:
		assert.Equal(t, agentclient.Healthy, state.State, "Healthy component/units should cause healthy Coordinator")
		assert.Equal(t, "Running", state.Message, "state message should be unchanged by healthy component updates")
	default:
		assert.Fail(t, "Coordinator's state didn't change")
	}

	// Set just the output unit to failed and make sure it is reported
	comp.State.Units[outputKey] = runtime.ComponentUnitState{
		State:   client.UnitStateFailed,
		Message: "invalid configuration",
	}
	runtimeChan <- comp
	coord.runLoopIteration(ctx)
	select {
	case state := <-stateChan:
		assert.Equal(t, agentclient.Degraded, state.State, "Failed output unit should cause Degraded Coordinator state")
		assert.Equal(t, "1 or more components/units in a failed state", state.Message, "state message should reflect failed output unit")
	default:
		assert.Fail(t, "Coordinator's state didn't change")
	}

	// Restore output unit to healthy and make sure Coordinator recovers
	comp.State.Units[outputKey] = runtime.ComponentUnitState{
		State:   client.UnitStateHealthy,
		Message: "everything is fine",
	}
	runtimeChan <- comp
	coord.runLoopIteration(ctx)
	select {
	case state := <-stateChan:
		assert.Equal(t, agentclient.Healthy, state.State, "Healthy output unit should restore coordinator state")
		assert.Equal(t, "Running", state.Message, "Healthy output unit should restore coordinator message")
	default:
		assert.Fail(t, "Coordinator's state didn't change")
	}
}

func TestCoordinatorReportsInvalidPolicy(t *testing.T) {
	// TODO: good candidate for the https://tip.golang.org/doc/go1.25#new-testingsynctest-package
	// Test that an obviously invalid policy sent to Coordinator will call
	// its Fail callback with an appropriate error, and will save and report
	// the error in its state until a policy update succeeds.
	ctx := t.Context()

	log, obs := loggertest.New("")
	defer func() {
		if t.Failed() {
			t.Log("test failed, coordinator logs below:")
			for _, l := range obs.TakeAll() {
				t.Log(l)
			}
		}
	}()

	tmpDir := t.TempDir()
	agentInfo, err := info.NewAgentInfo(ctx, false)
	require.NoError(t, err)
	upgradeMgr, err := upgrade.NewUpgrader(log, &artifact.Config{}, nil, agentInfo, new(upgrade.AgentWatcherHelper), ttl.NewTTLMarkerRegistry(nil, tmpDir))
	require.NoError(t, err, "errored when creating a new upgrader")

	// Channels have buffer length 1, so we don't have to run on multiple
	// goroutines.
	stateChan := make(chan State, 1)
	configChan := make(chan ConfigChange, 1)
	varsChan := make(chan []*transpiler.Vars, 1)
	coord := &Coordinator{
		logger: log,
		state: State{
			CoordinatorState:   agentclient.Healthy,
			CoordinatorMessage: "Running",
		},
		stateBroadcaster: &broadcaster.Broadcaster[State]{InputChan: stateChan},
		managerChans: managerChans{
			configManagerUpdate: configChan,
			varsManagerUpdate:   varsChan,
		},
		// Policy changes are sent to the upgrade manager, which scans it
		// for updated artifact URIs. We take advantage of this for the
		// test by sending an invalid artifact URI to trigger an error.
		upgradeMgr: upgradeMgr,
		// Add a placeholder runtime manager that will accept any updates
		runtimeMgr: &fakeRuntimeManager{},
		otelMgr:    &fakeOTelManager{},

		// Set valid but empty initial values for ast and vars
		currentCfg:         configuration.DefaultConfiguration(),
		vars:               emptyVars(t),
		ast:                emptyAST(t),
		componentPIDTicker: time.NewTicker(time.Second * 30),
		secretMarkerFunc:   testSecretMarkerFunc,
		agentInfo:          agentInfo,
	}

	// Send an invalid config update and confirm that Coordinator reports
	// the failure to the config change object.
	cfg := config.MustNewConfigFrom(`
name: "this config is invalid"
agent.download.sourceURI:
  the.problem: "URIs shouldn't have subfields"
`)
	cfgChange := &configChange{cfg: cfg}
	configChan <- cfgChange
	coord.runLoopIteration(ctx)
	assert.True(t, cfgChange.failed, "Policy with invalid field should have reported failed config change")
	require.ErrorContainsf(t,
		cfgChange.err,
		"failed to reload upgrade manager configuration",
		"wrong error message, expected 'failed to reload upgrade manager configuration...' got %v",
		cfgChange.err)
	require.ErrorContainsf(t,
		coord.configErr,
		"failed to reload upgrade manager configuration",
		"configErr should match policy failure, got %v", coord.configErr)

	stateChangeTimeout := 5 * time.Second
	select {
	case state := <-stateChan:
		assert.Equal(t, agentclient.Failed, state.State, "Failed policy change should cause Failed coordinator state")
		assert.Contains(t, state.Message, cfgChange.err.Error(), "Coordinator state should report failed policy change")

		// The component model update happens on a goroutine, thus the new state
		// might not have been sent yet. Therefore, a timeout is required.
	case <-time.After(stateChangeTimeout):
		t.Fatalf("timedout after %s waiting Coordinator's state to change", stateChangeTimeout)
	}

	// Send an empty vars update. This should regenerate the component model
	// based on the last good (empty) policy, producing a "successful" update,
	// but the overall reported state should still be Failed because the last
	// policy update didn't take effect.
	// (This check is based on a previous bug in which a vars update could
	// discard active policy errors.)
	varsChan <- emptyVars(t)
	t.Logf("after emptyVars statement")
	coord.runLoopIteration(ctx)

	assert.Error(t, coord.configErr, "Vars update shouldn't affect configErr")
	select {
	case state := <-stateChan:
		assert.Equal(t, agentclient.Failed, state.State, "Variable update should not overwrite policy error")
		assert.Contains(t, state.Message, cfgChange.err.Error(), "Variable update should not overwrite policy error")

		// The component model update happens on a goroutine, thus the new state
		// might not have been sent yet. Therefore, a timeout is required.
	case <-time.After(stateChangeTimeout):
		t.Fatalf("timedout after %s waiting Vars change to cause a state update",
			stateChangeTimeout)
	}

	// Finally, send an empty (valid) policy update and confirm that it
	// overwrites the previous error states.
	cfg = config.MustNewConfigFrom("")
	cfgChange = &configChange{cfg: cfg}
	configChan <- cfgChange
	coord.runLoopIteration(ctx)

	assert.NoError(t, coord.configErr, "Valid policy change should clear configErr")
	select {
	case state := <-stateChan:
		assert.Equal(t, agentclient.Healthy, state.State, "Valid policy change should produce healthy state")
		assert.Equal(t, state.Message, "Running", "Valid policy change should restore previous state message")

		// The component model update happens on a goroutine, thus the new state
		// might not have been sent yet. Therefore, a timeout is required.
	case <-time.After(stateChangeTimeout):
		t.Fatalf("timedout after %s waiting Policy change to cause a state update",
			stateChangeTimeout)
	}
}

func TestCoordinatorReportsComponentModelError(t *testing.T) {
	// Test the failure mode where a new policy passes the initial checks
	// and produces a valid AST, but can't be converted into a valid
	// component model (which we trigger with invalid conditional
	// expressions). In this case the resulting error should be stored
	// in Coordinator.componentModelErr, and reported by Coordinator.State.

	// Set a one-second timeout -- nothing here should block, but if it
	// does let's report a failure instead of timing out the test runner.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	logger := logp.NewLogger("testing")

	agentInfo, err := info.NewAgentInfo(t.Context(), false)
	require.NoError(t, err)

	// Channels have buffer length 1 so we don't have to run on multiple
	// goroutines.
	stateChan := make(chan State, 1)
	configChan := make(chan ConfigChange, 1)
	varsChan := make(chan []*transpiler.Vars, 1)
	coord := &Coordinator{
		logger: logger,
		state: State{
			CoordinatorState:   agentclient.Healthy,
			CoordinatorMessage: "Running",
		},
		stateBroadcaster: &broadcaster.Broadcaster[State]{InputChan: stateChan},
		managerChans: managerChans{
			configManagerUpdate: configChan,
			varsManagerUpdate:   varsChan,
		},
		// Add a placeholder runtime manager that will accept any updates
		runtimeMgr: &fakeRuntimeManager{},
		otelMgr:    &fakeOTelManager{},

		// Set valid but empty initial values for ast and vars
		vars:               emptyVars(t),
		ast:                emptyAST(t),
		componentPIDTicker: time.NewTicker(time.Second * 30),
		secretMarkerFunc:   testSecretMarkerFunc,
		agentInfo:          agentInfo,
	}

	// This configuration produces a valid AST but its EQL condition is
	// invalid, so its failure should be reported in componentModelErr.
	cfg := config.MustNewConfigFrom(`
inputs:
  - type: filestream
    condition: invalidExpression
`)
	cfgChange := &configChange{cfg: cfg}
	configChan <- cfgChange
	coord.runLoopIteration(ctx)

	require.Error(t, coord.componentModelErr)
	require.Contains(t, coord.componentModelErr.Error(), "rendering inputs failed:")
	select {
	case state := <-stateChan:
		assert.Equal(t, agentclient.Failed, state.State, "Failed component generation should cause failed state")
		assert.Contains(t, state.Message, "Invalid component model", "Failed component generation should report error")
	default:
		assert.Fail(t, "Config change should cause state update")
	}

	// Send an empty vars update. This should regenerate the component model
	// based on the last good (empty) policy, producing a "successful" update,
	// but the overall reported state should still be Failed because the last
	// policy update didn't take effect.
	// (This check is based on a previous bug in which a vars update could
	// discard active policy errors.)
	varsChan <- emptyVars(t)
	coord.runLoopIteration(ctx)

	assert.Error(t, coord.componentModelErr, "Vars update shouldn't affect componentModelErr")
	select {
	case state := <-stateChan:
		assert.Equal(t, agentclient.Failed, state.State, "Variable update should not overwrite component generation error")
		assert.Contains(t, state.Message, "Invalid component model", "Variable update should not overwrite component generation error")
	default:
		assert.Fail(t, "Vars change should cause state update")
	}

	// Send an empty (valid) policy update and confirm that it overwrites the
	// previous error states.
	cfg = config.MustNewConfigFrom("")
	cfgChange = &configChange{cfg: cfg}
	configChan <- cfgChange
	coord.runLoopIteration(ctx)

	assert.NoError(t, coord.configErr, "Valid policy change should clear configErr")
	assert.NoError(t, coord.componentModelErr, "Valid component model rebuild should clear componentModelErr")
	select {
	case state := <-stateChan:
		assert.Equal(t, agentclient.Healthy, state.State, "Valid policy change should produce healthy state")
		assert.Equal(t, state.Message, "Running", "Valid policy change should restore previous state message")
	default:
		assert.Fail(t, "Policy change should cause state update")
	}
}

func TestCoordinatorPolicyAppliedNotSetOnComponentModelError(t *testing.T) {
	// PolicyApplied must only become true once a policy has been successfully
	// turned into a component model. If generateComponentModel fails, callers
	// relying on PolicyApplied (e.g. the upgrade action handler waiting for
	// Endpoint to appear) must keep waiting for a usable policy instead of
	// concluding no component is configured.

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	logger := logp.NewLogger("testing")

	agentInfo, err := info.NewAgentInfo(t.Context(), false)
	require.NoError(t, err)

	stateChan := make(chan State, 1)
	configChan := make(chan ConfigChange, 1)
	varsChan := make(chan []*transpiler.Vars, 1)
	coord := &Coordinator{
		logger: logger,
		state: State{
			CoordinatorState:   agentclient.Healthy,
			CoordinatorMessage: "Running",
		},
		stateBroadcaster: &broadcaster.Broadcaster[State]{InputChan: stateChan},
		managerChans: managerChans{
			configManagerUpdate: configChan,
			varsManagerUpdate:   varsChan,
		},
		runtimeMgr:         &fakeRuntimeManager{},
		otelMgr:            &fakeOTelManager{},
		vars:               emptyVars(t),
		ast:                emptyAST(t),
		componentPIDTicker: time.NewTicker(time.Second * 30),
		secretMarkerFunc:   testSecretMarkerFunc,
		agentInfo:          agentInfo,
	}

	// Invalid EQL condition makes generateComponentModel fail.
	cfg := config.MustNewConfigFrom(`
inputs:
  - type: filestream
    condition: invalidExpression
`)
	cfgChange := &configChange{cfg: cfg}
	configChan <- cfgChange
	coord.runLoopIteration(ctx)

	require.Error(t, coord.componentModelErr)
	assert.False(t, coord.state.PolicyApplied, "PolicyApplied must stay false when component model generation fails")
	<-stateChan // drain the Failed state update

	// A subsequent valid policy should succeed and set PolicyApplied.
	cfg = config.MustNewConfigFrom("")
	cfgChange = &configChange{cfg: cfg}
	configChan <- cfgChange
	coord.runLoopIteration(ctx)

	assert.NoError(t, coord.componentModelErr)
	assert.True(t, coord.state.PolicyApplied, "PolicyApplied must be set once a policy is applied successfully")
}

func TestCoordinatorPolicyChangeUpdatesMonitorReloader(t *testing.T) {
	// Send a test policy to the Coordinator as a Config Manager update,
	// verify it generates the right component model and sends it to the
	// runtime manager, then send an empty policy and verify it calls
	// another runtime manager update with an empty component model.

	// Set a one-second timeout -- nothing here should block, but if it
	// does let's report a failure instead of timing out the test runner.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	log := logp.NewLogger("testing")

	configChan := make(chan ConfigChange, 1)

	// Create a mocked runtime manager that will report the update call
	runtimeManager := &fakeRuntimeManager{
		updateCallback: func(comp []pkgcomponent.Component) error {
			return nil
		},
	}

	monitoringServer := &fakeMonitoringServer{}
	newServerFn := func(*monitoringCfg.MonitoringConfig) (reload.ServerController, error) {
		return monitoringServer, nil
	}
	monitoringReloader := reload.NewServerReloader(newServerFn, log, monitoringCfg.DefaultConfig())

	secretMarkerCalled := false
	mockSecretMarkerFunc := func(*logger.Logger, *config.Config) error {
		secretMarkerCalled = true
		return nil
	}

	coord := &Coordinator{
		logger:           log,
		agentInfo:        &info.AgentInfo{},
		stateBroadcaster: broadcaster.New(State{}, 0, 0),
		managerChans: managerChans{
			configManagerUpdate: configChan,
		},
		runtimeMgr:         runtimeManager,
		otelMgr:            &fakeOTelManager{},
		vars:               emptyVars(t),
		componentPIDTicker: time.NewTicker(time.Second * 30),
		secretMarkerFunc:   mockSecretMarkerFunc,
	}
	coord.RegisterMonitoringServer(monitoringReloader)

	// Create a policy with one input and one output
	cfg := config.MustNewConfigFrom(`
outputs:
  default:
    type: elasticsearch
inputs:
  - id: test-input
    type: filestream
    use_output: default
`)

	// Send the policy change and make sure it was acknowledged.
	cfgChange := &configChange{cfg: cfg}
	configChan <- cfgChange
	coord.runLoopIteration(ctx)
	assert.True(t, cfgChange.acked, "Coordinator should ACK a successful policy change")

	assert.True(t, secretMarkerCalled, "secret marker should be called")

	// server is started by default
	assert.True(t, monitoringServer.startTriggered)
	assert.True(t, monitoringServer.isRunning)

	// disable monitoring
	cfgDisableMonitoring := config.MustNewConfigFrom(`
agent.monitoring.enabled: false
outputs:
  default:
    type: elasticsearch
inputs:
  - id: test-input
    type: filestream
    use_output: default
`)

	// Send the policy change and make sure it was acknowledged.
	monitoringServer.Reset()
	cfgChange = &configChange{cfg: cfgDisableMonitoring}
	configChan <- cfgChange
	coord.runLoopIteration(ctx)
	assert.True(t, cfgChange.acked, "Coordinator should ACK a successful policy change")

	// server is stopped: monitoring is disabled
	assert.True(t, monitoringServer.stopTriggered)
	assert.False(t, monitoringServer.isRunning)

	// enable monitoring
	cfgEnabledMonitoring := config.MustNewConfigFrom(`
agent.monitoring.enabled: true
outputs:
  default:
    type: elasticsearch
inputs:
  - id: test-input
    type: filestream
    use_output: default
`)

	// Send the policy change and make sure it was acknowledged.
	monitoringServer.Reset()
	cfgChange = &configChange{cfg: cfgEnabledMonitoring}
	configChan <- cfgChange
	coord.runLoopIteration(ctx)
	assert.True(t, cfgChange.acked, "Coordinator should ACK a successful policy change")

	// server is started again
	assert.True(t, monitoringServer.startTriggered)
	assert.True(t, monitoringServer.isRunning)

	// enable monitoring and disable metrics
	cfgEnabledMonitoringNoMetrics := config.MustNewConfigFrom(`
agent.monitoring.enabled: true
agent.monitoring.metrics: false
outputs:
  default:
    type: elasticsearch
inputs:
  - id: test-input
    type: filestream
    use_output: default
`)

	// Send the policy change and make sure it was acknowledged.
	monitoringServer.Reset()
	cfgChange = &configChange{cfg: cfgEnabledMonitoringNoMetrics}
	configChan <- cfgChange
	coord.runLoopIteration(ctx)
	assert.True(t, cfgChange.acked, "Coordinator should ACK a successful policy change")

	// server is running: monitoring.metrics is disabled does not have an effect
	assert.True(t, monitoringServer.isRunning)
}

func TestCoordinatorPolicyChangeUpdatesRuntimeAndOTelManager(t *testing.T) {
	// Send a test policy to the Coordinator as a Config Manager update,
	// verify it generates the right component model and sends it to the
	// runtime manager, then send an empty policy and verify it calls
	// another runtime manager update with an empty component model.

	// Set a one-second timeout -- nothing here should block, but if it
	// does let's report a failure instead of timing out the test runner.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	logger := logp.NewLogger("testing")

	configChan := make(chan ConfigChange, 1)

	// Create a mocked runtime manager that will report the update call
	var updated bool                        // Set by runtime manager callback
	var components []pkgcomponent.Component // Set by runtime manager callback
	runtimeManager := &fakeRuntimeManager{
		updateCallback: func(comp []pkgcomponent.Component) error {
			updated = true
			components = comp
			return nil
		},
	}
	var otelUpdated bool         // Set by otel manager callback
	var otelConfig *confmap.Conf // Set by otel manager callback
	otelManager := &fakeOTelManager{
		updateCollectorCallback: func(cfg *confmap.Conf) error {
			otelUpdated = true
			otelConfig = cfg
			return nil
		},
	}

	coord := &Coordinator{
		logger:           logger,
		agentInfo:        &info.AgentInfo{},
		stateBroadcaster: broadcaster.New(State{}, 0, 0),
		managerChans: managerChans{
			configManagerUpdate: configChan,
		},
		runtimeMgr:         runtimeManager,
		otelMgr:            otelManager,
		vars:               emptyVars(t),
		componentPIDTicker: time.NewTicker(time.Second * 30),
		secretMarkerFunc:   testSecretMarkerFunc,
	}

	// Create a policy with one input and one output (no otel configuration)
	cfg := config.MustNewConfigFrom(`
outputs:
  default:
    type: elasticsearch
inputs:
  - id: test-input
    type: filestream
    use_output: default
`)

	// Send the policy change and make sure it was acknowledged.
	cfgChange := &configChange{cfg: cfg}
	configChan <- cfgChange
	coord.runLoopIteration(ctx)
	assert.True(t, cfgChange.acked, "Coordinator should ACK a successful policy change")

	// Make sure the runtime manager received the expected component update.
	// An assert.Equal on the full component model doesn't play nice with
	// the embedded proto structs, so instead we verify the important fields
	// manually (sorry).
	assert.True(t, updated, "Runtime manager should be updated after a policy change")
	require.Equal(t, 1, len(components), "Test policy should generate one component")
	assert.True(t, otelUpdated, "OTel manager should be updated after a policy change")
	require.Nil(t, otelConfig, "OTel manager should not have any config")

	component := components[0]
	assert.Equal(t, "filestream-default", component.ID)
	require.NotNil(t, component.Err, "Input with no spec should produce a component error")
	assert.EqualError(t, pkgcomponent.ErrInputNotSupported, component.Err.Error(), "Input with no spec should report 'input not supported'")
	require.Equal(t, 2, len(component.Units))

	units := component.Units
	// Verify the input unit
	assert.Equal(t, "filestream-default-test-input", units[0].ID)
	assert.Equal(t, client.UnitTypeInput, units[0].Type)
	assert.Equal(t, "test-input", units[0].Config.Id)
	assert.Equal(t, "filestream", units[0].Config.Type)

	// Verify the output unit
	assert.Equal(t, "filestream-default", units[1].ID)
	assert.Equal(t, client.UnitTypeOutput, units[1].Type)
	assert.Equal(t, "elasticsearch", units[1].Config.Type)

	// Send a new config update that includes otel configuration
	updated = false
	components = nil
	otelUpdated = false
	otelConfig = nil
	cfg = config.MustNewConfigFrom(`
outputs:
  default:
    type: elasticsearch
inputs:
  - id: test-input
    type: filestream
    use_output: default
receivers:
  otlp:
processors:
  batch:
exporters:
  otlp:
service:
  pipelines:
    traces:
      receivers:
        - otlp
      exporters:
        - otlp
`)
	cfgChange = &configChange{cfg: cfg}
	configChan <- cfgChange
	coord.runLoopIteration(ctx)

	// Validate that the runtime manager and otel manager got the updated configuration
	assert.True(t, updated, "Runtime manager should be updated after a policy change")
	require.Equal(t, 1, len(components), "Test policy should generate one component")
	assert.True(t, otelUpdated, "OTel manager should be updated after a policy change")
	require.NotNil(t, otelConfig, "OTel manager should have a config")

	// Send a new empty config update and make sure the runtime manager
	// and otel manager receives that as well.
	updated = false
	components = nil
	otelUpdated = false
	otelConfig = nil
	cfgChange = &configChange{cfg: config.MustNewConfigFrom(nil)}
	configChan <- cfgChange
	coord.runLoopIteration(ctx)
	assert.True(t, cfgChange.acked, "empty policy should be acknowledged")
	assert.NoError(t, cfgChange.err, "config processing shouldn't report an error")
	assert.True(t, updated, "empty policy should cause runtime manager update")
	assert.Empty(t, components, "empty policy should produce empty component model")
	assert.True(t, otelUpdated, "empty policy should cause otel manager update")
	assert.Nil(t, otelConfig, "empty policy should cause otel manager to get nil config")
}

func TestCoordinatorPolicyChangeUpdatesComponentAgentInfo(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()

	originalValue := features.IncludeTagsInEvents()
	t.Cleanup(func() {
		err := features.Apply(config.MustNewConfigFrom(map[string]any{
			"agent.features.include_tags_in_events.enabled": originalValue,
		}))
		require.NoError(t, err)
	})

	configChan := make(chan ConfigChange, 1)
	var components []pkgcomponent.Component
	runtimeManager := &fakeRuntimeManager{
		updateCallback: func(comp []pkgcomponent.Component) error {
			components = comp
			return nil
		},
	}
	coord := &Coordinator{
		logger:           logp.NewLogger("testing"),
		agentInfo:        &info.AgentInfo{},
		stateBroadcaster: broadcaster.New(State{}, 0, 0),
		managerChans: managerChans{
			configManagerUpdate: configChan,
		},
		runtimeMgr:         runtimeManager,
		otelMgr:            &fakeOTelManager{},
		vars:               emptyVars(t),
		componentPIDTicker: time.NewTicker(time.Second * 30),
		secretMarkerFunc:   testSecretMarkerFunc,
	}

	newPolicy := func(enabled bool, tags string) *config.Config {
		return config.MustNewConfigFrom(fmt.Sprintf(`
agent:
  features:
    include_tags_in_events:
      enabled: %t
  tags: %s
outputs:
  default:
    type: elasticsearch
inputs:
  - id: test-input
    type: filestream
    use_output: default
`, enabled, tags))
	}

	// applyPolicy sends the policy and returns the agent info of the component model
	// that the runtime manager gets.
	applyPolicy := func(cfg *config.Config) (*proto.AgentInfo, error) {
		components = nil
		cfgChange := &configChange{cfg: cfg}
		configChan <- cfgChange
		coord.runLoopIteration(ctx)
		if !cfgChange.acked {
			return nil, errors.New("policy change was not acked")
		}
		if cfgChange.err != nil {
			return nil, fmt.Errorf("policy change failed: %w", cfgChange.err)
		}
		if len(components) != 1 {
			return nil, fmt.Errorf("got %d components, want 1", len(components))
		}
		if components[0].AgentInfo == nil {
			return nil, errors.New("component has no agent info")
		}
		return components[0].AgentInfo, nil
	}

	// The steps run in sequence on one coordinator. Each step depends on the previous one.
	t.Run("sends the tags to the components", func(t *testing.T) {
		policy := newPolicy(true, "[production]")
		agentInfo, err := applyPolicy(policy)
		require.NoError(t, err)
		assert.Equal(t, proto.AgentManagedMode_MANAGED, agentInfo.GetMode())
		assert.Equal(t, []string{"production"}, agentInfo.GetTags())
	})

	t.Run("sends a new tag", func(t *testing.T) {
		policy := newPolicy(true, "[production, team-payments]")
		agentInfo, err := applyPolicy(policy)
		require.NoError(t, err)
		assert.Equal(t, []string{"production", "team-payments"}, agentInfo.GetTags())
	})

	t.Run("clears the tags when the policy has none", func(t *testing.T) {
		policy := newPolicy(true, "[]")
		agentInfo, err := applyPolicy(policy)
		require.NoError(t, err)
		assert.Empty(t, agentInfo.GetTags())
	})

	t.Run("sends the tags again when they come back", func(t *testing.T) {
		policy := newPolicy(true, "[production]")
		agentInfo, err := applyPolicy(policy)
		require.NoError(t, err)
		assert.Equal(t, []string{"production"}, agentInfo.GetTags())
	})

	t.Run("drops the tags when the feature is off", func(t *testing.T) {
		policy := newPolicy(false, "[production]")
		agentInfo, err := applyPolicy(policy)
		require.NoError(t, err)
		assert.Empty(t, agentInfo.GetTags(), "the tags are not sent when include_tags_in_events is off")
	})
}

func TestCoordinatorPolicyChangeUpdatesRuntimeAndOTelManagerWithOtelComponents(t *testing.T) {
	// Send a test policy to the Coordinator as a Config Manager update,
	// verify it generates the right component model and sends components
	// to both the runtime manager and the otel manager.

	// Set a one-second timeout -- nothing here should block, but if it
	// does let's report a failure instead of timing out the test runner.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	logger := logp.NewLogger("testing")

	configChan := make(chan ConfigChange, 1)

	// Create a mocked runtime manager that will report the update call
	var updated bool                        // Set by runtime manager callback
	var components []pkgcomponent.Component // Set by runtime manager callback
	runtimeManager := &fakeRuntimeManager{
		updateCallback: func(comp []pkgcomponent.Component) error {
			updated = true
			components = comp
			return nil
		},
	}
	var otelUpdated bool         // Set by otel manager callback
	var otelConfig *confmap.Conf // Set by otel manager callback
	otelManager := &fakeOTelManager{
		updateCollectorCallback: func(cfg *confmap.Conf) error {
			otelUpdated = true
			otelConfig = cfg
			return nil
		},
	}

	// we need the filestream spec to be able to convert to Otel config
	componentSpec := pkgcomponent.InputRuntimeSpec{
		InputType:  "filestream",
		BinaryName: "elastic-otel-collector",
		Spec: pkgcomponent.InputSpec{
			Name: "filestream",
			Command: &pkgcomponent.CommandSpec{
				Args: []string{"filebeat"},
			},
			Platforms: []string{
				"linux/amd64",
				"linux/arm64",
				"darwin/amd64",
				"darwin/arm64",
				"windows/amd64",
				"windows/arm64",
				"container/amd64",
				"container/arm64",
			},
		},
	}

	platform, err := pkgcomponent.LoadPlatformDetail()
	require.NoError(t, err)
	specs, err := pkgcomponent.NewRuntimeSpecs(platform, []pkgcomponent.InputRuntimeSpec{componentSpec})
	require.NoError(t, err)

	monitoringMgr := newTestMonitoringMgr()
	coord := &Coordinator{
		logger:           logger,
		agentInfo:        &info.AgentInfo{},
		stateBroadcaster: broadcaster.New(State{}, 0, 0),
		managerChans: managerChans{
			configManagerUpdate: configChan,
		},
		monitorMgr:         monitoringMgr,
		runtimeMgr:         runtimeManager,
		otelMgr:            otelManager,
		specs:              specs,
		vars:               emptyVars(t),
		componentPIDTicker: time.NewTicker(time.Second * 30),
		secretMarkerFunc:   testSecretMarkerFunc,
	}

	t.Run("mixed policy", func(t *testing.T) {
		// Create a policy with one input and one output (no otel configuration)
		cfg := config.MustNewConfigFrom(`
agent.internal.runtime.filebeat.filestream: otel
outputs:
  default:
    type: elasticsearch
    hosts:
      - localhost:9200
inputs:
  - id: test-input
    type: filestream
    use_output: default
  - id: test-other-input
    type: system/metrics
    use_output: default
receivers:
  nop:
exporters:
  nop:
service:
  pipelines:
    traces:
      receivers:
        - nop
      exporters:
        - nop
`)

		// Send the policy change and make sure it was acknowledged.
		cfgChange := &configChange{cfg: cfg}
		configChan <- cfgChange
		coord.runLoopIteration(ctx)
		assert.True(t, cfgChange.acked, "Coordinator should ACK a successful policy change")
		assert.NoError(t, cfgChange.err, "config processing shouldn't report an error")

		// Make sure the runtime manager received the expected component update.
		// An assert.Equal on the full component model doesn't play nice with
		// the embedded proto structs, so instead we verify the important fields
		// manually (sorry).
		assert.True(t, updated, "Runtime manager should be updated after a policy change")
		require.Equal(t, 1, len(components), "Test policy should generate one component")
		assert.True(t, otelUpdated, "OTel manager should be updated after a policy change")
		require.NotNil(t, otelConfig, "OTel manager should have config")

		runtimeComponent := components[0]
		assert.Equal(t, "system/metrics-default", runtimeComponent.ID)
		require.NotNil(t, runtimeComponent.Err, "Input with no spec should produce a component error")
		assert.EqualError(t, pkgcomponent.ErrInputNotSupported, runtimeComponent.Err.Error(), "Input with no spec should report 'input not supported'")
		require.Equal(t, 2, len(runtimeComponent.Units))

		units := runtimeComponent.Units
		// Verify the input unit
		assert.Equal(t, "system/metrics-default-test-other-input", units[0].ID)
		assert.Equal(t, client.UnitTypeInput, units[0].Type)
		assert.Equal(t, "test-other-input", units[0].Config.Id)
		assert.Equal(t, "system/metrics", units[0].Config.Type)

		// Verify the output unit
		assert.Equal(t, "system/metrics-default", units[1].ID)
		assert.Equal(t, client.UnitTypeOutput, units[1].Type)
		assert.Equal(t, "elasticsearch", units[1].Config.Type)
	})

	t.Run("unsupported otel output option", func(t *testing.T) {
		// Create a policy with one input and one output (no otel configuration)
		cfg := config.MustNewConfigFrom(`
agent.internal.runtime.filebeat.filestream: otel
outputs:
  default:
    type: elasticsearch
    hosts:
      - localhost:9200
    indices: [] # not supported by the elasticsearch exporter
inputs:
  - id: test-input
    type: filestream
    use_output: default
  - id: test-other-input
    type: system/metrics
    use_output: default
receivers:
  nop:
exporters:
  nop:
service:
  pipelines:
    traces:
      receivers:
        - nop
      exporters:
        - nop
`)

		// Send the policy change and make sure it was acknowledged.
		cfgChange := &configChange{cfg: cfg}
		configChan <- cfgChange
		coord.runLoopIteration(ctx)
		assert.True(t, cfgChange.acked, "Coordinator should ACK a successful policy change")
		assert.NoError(t, cfgChange.err, "config processing shouldn't report an error")

		// Make sure the runtime manager received the expected component update.
		// An assert.Equal on the full component model doesn't play nice with
		// the embedded proto structs, so instead we verify the important fields
		// manually (sorry).
		assert.True(t, updated, "Runtime manager should be updated after a policy change")
		assert.True(t, otelUpdated, "OTel manager should be updated after a policy change")
		require.NotNil(t, otelConfig, "OTel manager should have config")

		assert.Len(t, components, 2, "both components should be assigned to the runtime manager")
	})

	t.Run("dynamic input switches from otel to process runtime", func(t *testing.T) {
		// Reset state from previous test runs
		updated = false
		otelUpdated = false
		components = nil
		otelConfig = nil

		// Track components sent to otel manager
		var otelComponents []pkgcomponent.Component
		otelManager.updateComponentCallback = func(comp []pkgcomponent.Component) error {
			otelComponents = comp
			return nil
		}

		// Create a policy where the filestream input uses a dynamic provider variable.
		// The input is configured for OTel runtime, but because it uses a dynamic provider
		// (local_dynamic) and dynamic_inputs is set to "process", it should be switched to process runtime.
		cfg := config.MustNewConfigFrom(`
agent.internal.runtime.filebeat.filestream: otel
agent.internal.runtime.dynamic_inputs: process
outputs:
  default:
    type: elasticsearch
    hosts:
      - localhost:9200
inputs:
  - id: dynamic-filestream-input
    type: filestream
    path: "${local_dynamic.path}"
    use_output: default
`)

		// Create vars with the local_dynamic provider mapping
		// The vars tree needs to have local_dynamic.path so the variable ${local_dynamic.path} can be resolved
		vars, err := transpiler.NewVarsWithProcessors("local_dynamic-1", map[string]interface{}{
			"local_dynamic": map[string]interface{}{
				"path": "/var/log/test.log",
			},
		}, "local_dynamic", nil, nil, "", "local_dynamic")
		require.NoError(t, err)
		coord.vars = []*transpiler.Vars{vars}

		// Set a varsMgr so the coordinator can generate the component model
		coord.varsMgr = &fakeVarsManager{}

		// Send the policy change
		cfgChange := &configChange{cfg: cfg}
		configChan <- cfgChange
		coord.runLoopIteration(ctx)
		assert.True(t, cfgChange.acked, "Coordinator should ACK a successful policy change")
		assert.NoError(t, cfgChange.err, "config processing shouldn't report an error")

		// The component should be routed to the runtime manager (not otel) because
		// it uses a dynamic provider variable
		assert.True(t, updated, "Runtime manager should be updated")
		assert.True(t, otelUpdated, "OTel manager should be updated")

		// Find the filestream component - it should be in the runtime manager's components
		// because dynamic inputs are switched to process runtime
		var filestreamInRuntime bool
		for _, comp := range components {
			if strings.Contains(comp.ID, "filestream") {
				filestreamInRuntime = true
				assert.Equal(t, pkgcomponent.ProcessRuntimeManager, comp.RuntimeManager,
					"Dynamic input should use ProcessRuntimeManager")
				assert.True(t, comp.Dynamic, "Component should be marked as dynamic")
			}
		}

		// The filestream should NOT be in otel components
		var filestreamInOtel bool
		for _, comp := range otelComponents {
			if strings.Contains(comp.ID, "filestream") {
				filestreamInOtel = true
			}
		}

		assert.True(t, filestreamInRuntime, "Dynamic filestream input should be in runtime manager")
		assert.False(t, filestreamInOtel, "Dynamic filestream input should NOT be in otel manager")
	})

	t.Run("dynamic input using only static variables stays on the otel runtime", func(t *testing.T) {
		// Reset state from previous test runs
		updated = false
		otelUpdated = false
		components = nil
		otelConfig = nil

		// Track components sent to otel manager
		var otelComponents []pkgcomponent.Component
		otelManager.updateComponentCallback = func(comp []pkgcomponent.Component) error {
			otelComponents = comp
			return nil
		}

		// The input only references a variable declared as static, so even though it is rendered
		// from a dynamic provider it can't cause configuration reloads and must stay on otel.
		cfg := config.MustNewConfigFrom(`
agent.internal.runtime.filebeat.filestream: otel
agent.internal.runtime.dynamic_inputs:
  default: process
  static_variables:
    - local_dynamic.group
outputs:
  default:
    type: elasticsearch
    hosts:
      - localhost:9200
inputs:
  - id: static-filestream-input
    type: filestream
    path: "/var/log/${local_dynamic.group}.log"
    use_output: default
`)

		vars, err := transpiler.NewVarsWithProcessors("local_dynamic-1", map[string]interface{}{
			"local_dynamic": map[string]interface{}{
				"group": "shared",
				"path":  "/var/log/test.log",
			},
		}, "local_dynamic", nil, nil, "", "local_dynamic")
		require.NoError(t, err)
		coord.vars = []*transpiler.Vars{vars}
		coord.varsMgr = &fakeVarsManager{}

		cfgChange := &configChange{cfg: cfg}
		configChan <- cfgChange
		coord.runLoopIteration(ctx)
		assert.True(t, cfgChange.acked, "Coordinator should ACK a successful policy change")
		assert.NoError(t, cfgChange.err, "config processing shouldn't report an error")

		var filestreamInOtel bool
		for _, comp := range otelComponents {
			if strings.Contains(comp.ID, "filestream") {
				filestreamInOtel = true
				assert.Equal(t, pkgcomponent.OtelRuntimeManager, comp.RuntimeManager,
					"input using only static variables should stay on the otel runtime")
				assert.False(t, comp.Dynamic, "component should not be marked as dynamic")
			}
		}
		for _, comp := range components {
			assert.NotContains(t, comp.ID, "filestream",
				"input using only static variables should not be moved to the process runtime")
		}
		assert.True(t, filestreamInOtel, "filestream input should be handled by the otel manager")
	})

}

func TestCoordinatorManagesComponentWorkDirs(t *testing.T) {
	// Send a test policy to the Coordinator as a Config Manager update,
	// verify it creates a working directory for the component, keeps that working directory as the component
	// moves to a different runtime, then deletes it after the component is stopped.
	pathstest.SetTop(t, t.TempDir())

	logger := logp.NewLogger("testing")

	configChan := make(chan ConfigChange, 1)
	updateChan := make(chan runtime.ComponentComponentState, 1)

	// Create a mocked runtime manager that will report the update call
	runtimeManager := &fakeRuntimeManager{}
	otelManager := &fakeOTelManager{}

	// we need the filestream spec to be able to convert to Otel config
	componentSpec := pkgcomponent.InputRuntimeSpec{
		InputType:  "filestream",
		BinaryName: "elastic-otel-collector",
		Spec: pkgcomponent.InputSpec{
			Name: "filestream",
			Command: &pkgcomponent.CommandSpec{
				Args: []string{"filebeat"},
			},
			Platforms: []string{
				"linux/amd64",
				"linux/arm64",
				"darwin/amd64",
				"darwin/arm64",
				"windows/amd64",
				"container/amd64",
				"container/arm64",
			},
		},
	}

	platform, err := pkgcomponent.LoadPlatformDetail()
	require.NoError(t, err)
	specs, err := pkgcomponent.NewRuntimeSpecs(platform, []pkgcomponent.InputRuntimeSpec{componentSpec})
	require.NoError(t, err)

	monitoringMgr := newTestMonitoringMgr()
	coord := &Coordinator{
		logger:           logger,
		agentInfo:        &info.AgentInfo{},
		stateBroadcaster: broadcaster.New(State{}, 0, 0),
		managerChans: managerChans{
			configManagerUpdate:  configChan,
			runtimeManagerUpdate: updateChan,
		},
		monitorMgr:         monitoringMgr,
		runtimeMgr:         runtimeManager,
		otelMgr:            otelManager,
		specs:              specs,
		vars:               emptyVars(t),
		componentPIDTicker: time.NewTicker(time.Second * 30),
		secretMarkerFunc:   testSecretMarkerFunc,
	}

	var workDirPath string
	var workDirCreated time.Time

	t.Run("run in process manager", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		t.Cleanup(cancel)
		// Create a policy with one input and one output (no otel configuration)
		cfg := config.MustNewConfigFrom(`
agent.internal.runtime.filebeat.filestream: process
outputs:
  default:
    type: elasticsearch
    hosts:
      - localhost:9200
inputs:
  - id: test-input
    type: filestream
    use_output: default
`)

		// Send the policy change and make sure it was acknowledged.
		cfgChange := &configChange{cfg: cfg}
		configChan <- cfgChange
		coord.runLoopIteration(ctx)
		assert.True(t, cfgChange.acked, "Coordinator should ACK a successful policy change")
		assert.NoError(t, cfgChange.err, "config processing shouldn't report an error")
		require.Len(t, coord.componentModel, 1, "there should be one component")
		workDirPath = coord.componentModel[0].WorkDirPath(paths.Run())
		stat, err := os.Stat(workDirPath)
		require.NoError(t, err, "component working directory should exist")
		assert.True(t, stat.IsDir(), "component working directory should exist")
		workDirCreated = stat.ModTime()
	})

	t.Run("run in otel manager", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		t.Cleanup(cancel)
		// Create a policy with one input and one output (no otel configuration)
		cfg := config.MustNewConfigFrom(`
agent.internal.runtime.filebeat.filestream: otel
outputs:
  default:
    type: elasticsearch
    hosts:
      - localhost:9200
inputs:
  - id: test-input
    type: filestream
    use_output: default
`)

		// Send the policy change and make sure it was acknowledged.
		cfgChange := &configChange{cfg: cfg}
		configChan <- cfgChange
		coord.runLoopIteration(ctx)
		assert.True(t, cfgChange.acked, "Coordinator should ACK a successful policy change")
		assert.NoError(t, cfgChange.err, "config processing shouldn't report an error")
		require.Len(t, coord.componentModel, 1, "there should be one component")
		compState := runtime.ComponentComponentState{
			Component: pkgcomponent.Component{
				ID: "filestream-default",
			},
			State: runtime.ComponentState{
				State: client.UnitStateStopped,
			},
		}
		updateChan <- compState
		coord.runLoopIteration(ctx)
		stat, err := os.Stat(workDirPath)
		require.NoError(t, err, "component working directory should exist")
		assert.True(t, stat.IsDir(), "component working directory should exist")
		assert.Equal(t, workDirCreated, stat.ModTime(), "component working directory shouldn't have been modified")
	})
	t.Run("remove component", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		t.Cleanup(cancel)
		// Create a policy with one input and one output (no otel configuration)
		cfg := config.MustNewConfigFrom(`
outputs:
  default:
    type: elasticsearch
    hosts:
      - localhost:9200
inputs: []
`)

		// Send the policy change and make sure it was acknowledged.
		cfgChange := &configChange{cfg: cfg}
		configChan <- cfgChange
		coord.runLoopIteration(ctx)
		assert.True(t, cfgChange.acked, "Coordinator should ACK a successful policy change")
		assert.NoError(t, cfgChange.err, "config processing shouldn't report an error")
		require.Len(t, coord.componentModel, 0, "there should be one component")

		compState := runtime.ComponentComponentState{
			Component: pkgcomponent.Component{
				ID: "filestream-default",
			},
			State: runtime.ComponentState{
				State: client.UnitStateStopped,
			},
		}
		updateChan <- compState
		coord.runLoopIteration(ctx)
		assert.NoDirExists(t, workDirPath, "component working directory shouldn't exist anymore")
	})

}

func TestCoordinatorReportsRuntimeManagerUpdateFailure(t *testing.T) {
	// Set a one-second timeout -- nothing here should block, but if it
	// does let's report a failure instead of timing out the test runner.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	logger := logp.NewLogger("testing")

	configChan := make(chan ConfigChange, 1)
	updateErrChan := make(chan error, 1)

	const errorStr = "update failed for testing reasons"
	// Create a mocked runtime manager that always reports an error
	runtimeManager := &fakeRuntimeManager{
		updateCallback: func(comp []pkgcomponent.Component) error {
			return errors.New(errorStr)
		},
		errChan: updateErrChan,
	}

	coord := &Coordinator{
		logger:           logger,
		agentInfo:        &info.AgentInfo{},
		stateBroadcaster: broadcaster.New(State{}, 0, 0),
		managerChans: managerChans{
			configManagerUpdate: configChan,
			// Give coordinator the same error channel we set on the runtime
			// manager, so it receives the update result.
			runtimeManagerError: updateErrChan,
		},
		runtimeMgr:         runtimeManager,
		otelMgr:            &fakeOTelManager{},
		vars:               emptyVars(t),
		componentPIDTicker: time.NewTicker(time.Second * 30),
		secretMarkerFunc:   testSecretMarkerFunc,
	}

	// Send an empty policy which should forward an empty component model to
	// the runtime manager (which we have set up to report an error).
	cfg := config.MustNewConfigFrom(nil)
	configChange := &configChange{cfg: cfg}
	configChan <- configChange
	coord.runLoopIteration(ctx)

	// Make sure the config change was acknowledged to the config manager
	// (the failure is not reported here since it happens asynchronously; it
	// will appear in the coordinator state afterwards.)
	assert.True(t, configChange.acked, "Config change should be acknowledged to the config manager")
	assert.NoError(t, configChange.err, "Config change with async error should succeed")

	// Now do another run loop iteration to let the update error propagate,
	// and make sure it is reported correctly.
	coord.runLoopIteration(ctx)
	require.Error(t, coord.runtimeUpdateErr, "Runtime update failure should be saved in runtimeUpdateErr")
	assert.Equal(t, errorStr, coord.runtimeUpdateErr.Error(), "runtimeUpdateErr should match the error reported by the runtime manager")

	// Make sure the error appears in the Coordinator state.
	state := coord.State()
	assert.Equal(t, agentclient.Failed, state.State, "Failed policy update should cause failed Coordinator")
	assert.Contains(t, state.Message, errorStr, "Failed policy update should be reported in Coordinator state message")
}

func TestCoordinatorReportsOTelManagerUpdateFailure(t *testing.T) {
	// Set a one-second timeout -- nothing here should block, but if it
	// does let's report a failure instead of timing out the test runner.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	logger := logp.NewLogger("testing")

	configChan := make(chan ConfigChange, 1)
	updateErrChan := make(chan error, 1)

	// Create a mocked otel manager that always reports an error
	const errorStr = "update failed for testing reasons"
	runtimeManager := &fakeRuntimeManager{}
	otelManager := &fakeOTelManager{
		updateCollectorCallback: func(retrieved *confmap.Conf) error {
			return errors.New(errorStr)
		},
		errChan: updateErrChan,
	}

	coord := &Coordinator{
		logger:           logger,
		agentInfo:        &info.AgentInfo{},
		stateBroadcaster: broadcaster.New(State{}, 0, 0),
		managerChans: managerChans{
			configManagerUpdate: configChan,
			// Give coordinator the same error channel we set on the otel
			// manager, so it receives the update result.
			otelManagerError: updateErrChan,
		},
		runtimeMgr:         runtimeManager,
		otelMgr:            otelManager,
		vars:               emptyVars(t),
		componentPIDTicker: time.NewTicker(time.Second * 30),
		secretMarkerFunc:   testSecretMarkerFunc,
	}

	// Send an empty policy which should forward an empty component model to
	// the otel manager (which we have set up to report an error).
	cfg := config.MustNewConfigFrom(nil)
	configChange := &configChange{cfg: cfg}
	configChan <- configChange
	coord.runLoopIteration(ctx)

	// Make sure the config change was acknowledged to the config manager
	// (the failure is not reported here since it happens asynchronously; it
	// will appear in the coordinator state afterwards.)
	assert.True(t, configChange.acked, "Config change should be acknowledged to the config manager")
	assert.NoError(t, configChange.err, "Config change with async error should succeed")

	// Now do another run loop iteration to let the update error propagate,
	// and make sure it is reported correctly.
	coord.runLoopIteration(ctx)
	require.Error(t, coord.otelErr, "OTel update failure should be saved in otelErr")
	assert.Equal(t, errorStr, coord.otelErr.Error(), "otelErr should match the error reported by the otel manager")

	// Make sure the error appears in the Coordinator state.
	state := coord.State()
	assert.Equal(t, agentclient.Failed, state.State, "Failed policy update should cause failed Coordinator")
	assert.Contains(t, state.Message, errorStr, "Failed policy update should be reported in Coordinator state message")
}

type ackErrConfigChange struct {
	cfg *config.Config
	err error
}

func (l *ackErrConfigChange) Config() *config.Config { return l.cfg }
func (l *ackErrConfigChange) Ack() error             { return l.err }
func (l *ackErrConfigChange) Fail(err error)         {}

func TestCoordinatorReportsConfigChangeAckFailure(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	logger := logp.NewLogger("testing")

	stateChan := make(chan State, 1)
	configChan := make(chan ConfigChange, 1)

	coord := &Coordinator{
		logger:    logger,
		agentInfo: &info.AgentInfo{},
		state: State{
			CoordinatorState:   agentclient.Healthy,
			CoordinatorMessage: "Running",
		},

		stateBroadcaster: &broadcaster.Broadcaster[State]{InputChan: stateChan},
		managerChans: managerChans{
			configManagerUpdate: configChan,
		},
		runtimeMgr:         &fakeRuntimeManager{},
		otelMgr:            &fakeOTelManager{},
		vars:               emptyVars(t),
		componentPIDTicker: time.NewTicker(time.Second * 30),
		secretMarkerFunc:   testSecretMarkerFunc,
		isManaged:          true,
	}

	const errorStr = "ack failed for testing reasons"
	configChan <- &ackErrConfigChange{
		cfg: config.MustNewConfigFrom(nil),
		err: errors.New(errorStr),
	}
	coord.runLoopIteration(ctx)
	require.Error(t, coord.actionsErr, "Ack failure should be saved in actionsErr")
	select {
	case state := <-stateChan:
		assert.Equal(t, agentclient.Failed, state.State, "Ack failure should cause failed Coordinator")
		assert.Contains(t, state.Message, errorStr, "Ack failure should be reported in Coordinator state message")
	default:
		assert.Fail(t, "Policy change should cause state update")
	}

	// A subsequent successful policy change ack should clear actionsErr.
	configChan <- &configChange{cfg: config.MustNewConfigFrom(nil)}
	coord.runLoopIteration(ctx)

	assert.NoError(t, coord.actionsErr, "Successful Ack should clear actionsErr")
	select {
	case state := <-stateChan:
		assert.Equal(t, agentclient.Healthy, state.State, "Successful Ack should restore healthy state")
		assert.Equal(t, state.Message, "Running", "Successful Ack should restore previous state message")
	default:
		assert.Fail(t, "Policy change should cause state update")
	}
}

func TestCoordinatorAppliesVarsToPolicy(t *testing.T) {
	// Make sure:
	// - An input unit that depends on an undefined variable is not created
	// - A vars update defining the variable causes the input to be created
	// - A second vars update changing the variable updates the input config
	// Set a one-second timeout -- nothing here should block, but if it
	// does let's report a failure instead of timing out the test runner.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	logger := logp.NewLogger("testing")

	configChan := make(chan ConfigChange, 1)
	varsChan := make(chan []*transpiler.Vars, 1)

	// Create a mocked runtime manager that will report the update call
	var updated bool                        // Set by runtime manager callback
	var components []pkgcomponent.Component // Set by runtime manager callback
	runtimeManager := &fakeRuntimeManager{
		updateCallback: func(comp []pkgcomponent.Component) error {
			updated = true
			components = comp
			return nil
		},
	}

	coord := &Coordinator{
		logger:           logger,
		agentInfo:        &info.AgentInfo{},
		stateBroadcaster: broadcaster.New(State{}, 0, 0),
		managerChans: managerChans{
			configManagerUpdate: configChan,
			varsManagerUpdate:   varsChan,
		},
		runtimeMgr:         runtimeManager,
		otelMgr:            &fakeOTelManager{},
		vars:               emptyVars(t),
		componentPIDTicker: time.NewTicker(time.Second * 30),
		secretMarkerFunc:   testSecretMarkerFunc,
	}

	// Create a policy with one input and one output
	cfg := config.MustNewConfigFrom(`
outputs:
  default:
    type: elasticsearch
inputs:
  - id: ${TEST_VAR}
    type: filestream
    use_output: default
`)

	// Send the policy change and make sure it was acknowledged, but produced
	// empty components.
	cfgChange := &configChange{cfg: cfg}
	configChan <- cfgChange
	coord.runLoopIteration(ctx)
	assert.True(t, cfgChange.acked, "Coordinator should ACK a successful policy change")
	assert.True(t, updated, "Runtime manager should receive a component model update")
	assert.Empty(t, components, "Input with missing variable shouldn't create a component")

	// Send a vars update adding the undefined variable
	updated = false
	components = nil
	vars, err := transpiler.NewVars("", map[string]interface{}{
		"TEST_VAR": "input-id",
	}, nil, "")
	require.NoError(t, err, "Vars creation must succeed")
	varsChan <- []*transpiler.Vars{vars}
	coord.runLoopIteration(ctx)

	// Check that there was a component model update and that it has a component
	// with the right id.
	assert.True(t, updated, "Runtime manager should receive a component model update")
	assert.Equal(t, 1, len(components), "Input with valid variable should create a component")
	assert.Equal(t, 2, len(components[0].Units), "Component config should have 2 units (one input and one output)")
	assert.Equal(t, "input-id", components[0].Units[0].Config.Id)

	// Send a new vars update changing the variable
	updated = false
	components = nil
	vars, err = transpiler.NewVars("", map[string]interface{}{
		"TEST_VAR": "changed-input-id",
	}, nil, "")
	require.NoError(t, err, "Vars creation must succeed")
	varsChan <- []*transpiler.Vars{vars}
	coord.runLoopIteration(ctx)

	// Check that the new value appears in the component model
	assert.True(t, updated, "Runtime manager should receive a component model update")
	assert.Equal(t, 1, len(components), "Input with valid variable should create a component")
	assert.Equal(t, 2, len(components[0].Units), "Component config should have 2 units (one input and one output)")
	assert.Equal(t, "changed-input-id", components[0].Units[0].Config.Id)
}

func TestCoordinatorReportsOverrideState(t *testing.T) {
	// Set a one-second timeout -- nothing here should block, but if it
	// does let's report a failure instead of timing out the test runner.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	// Channels have buffer length 1 so we don't have to run on multiple
	// goroutines.
	stateChan := make(chan State, 1)
	overrideStateChan := make(chan *coordinatorOverrideState, 1)
	coord := &Coordinator{
		state: State{
			CoordinatorState:   agentclient.Degraded,
			CoordinatorMessage: "Running",
		},
		stateBroadcaster: &broadcaster.Broadcaster[State]{
			InputChan: stateChan,
		},
		overrideStateChan:  overrideStateChan,
		componentPIDTicker: time.NewTicker(time.Second * 30),
	}
	// Send an error via the vars manager channel, and let Coordinator update
	overrideStateChan <- &coordinatorOverrideState{
		state:   agentclient.Upgrading,
		message: "Upgrading",
	}
	coord.runLoopIteration(ctx)

	// Make sure the new reported state reflects the override state
	select {
	case state := <-stateChan:
		assert.Equal(t, agentclient.Upgrading, state.State, "expected Upgrading State")
		assert.Equal(t, "Upgrading", state.Message, "state message should match override state")
	default:
		assert.Fail(t, "Coordinator's state didn't change")
	}

	// Clear the override state and let Coordinator update
	overrideStateChan <- nil
	coord.runLoopIteration(ctx)

	// Make sure the state has returned to its original value
	select {
	case state := <-stateChan:
		assert.Equal(t, agentclient.Degraded, state.State, "state should return to its original value")
		assert.Equal(t, "Running", state.Message, "state message should return to its original value")
	default:
		assert.Fail(t, "Coordinator's state didn't change")
	}
}

func TestCoordinatorTranslatesOtelStatusToComponentState(t *testing.T) {
	// Send an otel status to the coordinator, verify that it is correctly reflected in the component state

	// Set a one-second timeout -- nothing here should block, but if it
	// does let's report a failure instead of timing out the test runner.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	logger := logp.NewLogger("testing")

	runtimeStateChan := make(chan runtime.ComponentComponentState)
	componentUpdateChan := make(chan []runtime.ComponentComponentState)

	otelComponent := pkgcomponent.Component{
		ID:             "filestream-default",
		InputType:      "filestream",
		OutputType:     "elasticsearch",
		RuntimeManager: pkgcomponent.OtelRuntimeManager,
		InputSpec: &pkgcomponent.InputRuntimeSpec{
			BinaryName: "elastic-otel-collector",
			Spec: pkgcomponent.InputSpec{
				Command: &pkgcomponent.CommandSpec{
					Args: []string{"filebeat"},
				},
			},
		},
		Units: []pkgcomponent.Unit{
			{
				ID:   "filestream-unit",
				Type: client.UnitTypeInput,
				Config: &proto.UnitExpectedConfig{
					Streams: []*proto.Stream{
						{Id: "test-1"},
						{Id: "test-2"},
					},
				},
			},
			{
				ID:   "filestream-default",
				Type: client.UnitTypeOutput,
			},
		},
	}

	processComponent := otelComponent
	processComponent.RuntimeManager = pkgcomponent.ProcessRuntimeManager
	processComponent.ID = "filestream-process"

	compState := runtime.ComponentComponentState{
		Component: otelComponent,
		State: runtime.ComponentState{
			State: client.UnitStateHealthy,
		},
	}

	coord := &Coordinator{
		logger:           logger,
		agentInfo:        &info.AgentInfo{},
		stateBroadcaster: broadcaster.New(State{}, 0, 0),
		managerChans: managerChans{
			otelManagerComponentUpdate: componentUpdateChan,
			runtimeManagerUpdate:       make(chan runtime.ComponentComponentState),
		},
		state: State{},
	}

	// start runtime status watching
	go coord.watchRuntimeComponents(ctx, runtimeStateChan, componentUpdateChan)

	// no component status
	assert.Empty(t, coord.state.Components)

	// push the otel component state into the coordinator
	select {
	case componentUpdateChan <- []runtime.ComponentComponentState{compState}:
	case <-ctx.Done():
		t.Fatal("timeout waiting for coordinator to receive status")
	}

	select {
	case componentState := <-coord.managerChans.runtimeManagerUpdate:
		coord.applyComponentState(componentState)
	case <-ctx.Done():
		t.Fatal("timeout waiting for coordinator to receive status")
	}

	assert.Len(t, coord.state.Components, 1)

	// push the process component state into the coordinator
	select {
	case runtimeStateChan <- runtime.ComponentComponentState{
		Component: processComponent,
		State: runtime.ComponentState{
			State: client.UnitStateHealthy,
		},
	}:
	case <-ctx.Done():
		t.Fatal("timeout waiting for coordinator to receive status")
	}

	select {
	case componentState := <-coord.managerChans.runtimeManagerUpdate:
		coord.applyComponentState(componentState)
	case <-ctx.Done():
		t.Fatal("timeout waiting for coordinator to receive status")
	}

	assert.Len(t, coord.state.Components, 2)

	// Push a stopped status, there should be no otel component state
	select {
	case componentUpdateChan <- []runtime.ComponentComponentState{{
		Component: otelComponent,
		State: runtime.ComponentState{
			State: client.UnitStateStopped,
		},
	}}:
	case <-ctx.Done():
		t.Fatal("timeout waiting for coordinator to receive status")
	}

	select {
	case componentState := <-coord.managerChans.runtimeManagerUpdate:
		coord.applyComponentState(componentState)
	case <-ctx.Done():
		t.Fatal("timeout waiting for coordinator to receive status")
	}

	assert.Len(t, coord.state.Components, 1)
}

func TestCoordinatorInitiatesUpgrade(t *testing.T) {
	// Set a one-second timeout -- nothing here should block, but if it
	// does let's report a failure instead of timing out the test runner.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	// overrideStateChan has buffer 2 so we can run on a single goroutine,
	// since a successful upgrade sets the override state twice.
	overrideStateChan := make(chan *coordinatorOverrideState, 2)

	// similarly, upgradeDetailsChan is a buffered channel as well.
	upgradeDetailsChan := make(chan *details.Details, 2)

	// Create a manager that will allow upgrade attempts but return a failure
	// from Upgrade itself (success requires testing ReExec and we aren't
	// quite ready to do that yet).
	upgradeMgr := &fakeUpgradeManager{
		upgradeable: true,
		upgradeErr:  errors.New("failed upgrade"),
	}

	coord := &Coordinator{
		stateBroadcaster:   broadcaster.New(State{}, 0, 0),
		overrideStateChan:  overrideStateChan,
		upgradeDetailsChan: upgradeDetailsChan,
		upgradeMgr:         upgradeMgr,
		logger:             logp.NewLogger("testing"),
	}

	// Call upgrade and make sure the upgrade manager receives an Upgrade call
	err := coord.Upgrade(ctx, "1.2.3", nil, nil, WithSkipVerifyOverride(false), WithSkipDefaultPgp(false))
	assert.True(t, upgradeMgr.upgradeCalled, "Coordinator Upgrade should call upgrade manager Upgrade")
	assert.Equal(t, upgradeMgr.upgradeErr, err, "Upgrade should report upgrade manager error")

	// Make sure the expected override states were set
	select {
	case overrideState := <-overrideStateChan:
		require.NotNil(t, overrideState, "Upgrade should cause nonempty override state")
		assert.Equal(t, agentclient.Upgrading, overrideState.state, "Expected Upgrade to set override state to Upgrading")
		assert.Equal(t, "Upgrading to version 1.2.3", overrideState.message, "Expected Upgrade to set upgrading override message")
	default:
		assert.Fail(t, "Upgrade should have set an override state")
	}
	select {
	case overrideState := <-overrideStateChan:
		assert.Nil(t, overrideState, "Failed upgrade should clear the override state")
	default:
		assert.Fail(t, "Failed upgrade should clear the override state")
	}
}

func TestCoordinator_UnmanagedAgent_SkipsMigrate(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	// overrideStateChan has buffer 2 so we can run on a single goroutine,
	// since a successful upgrade sets the override state twice.
	overrideStateChan := make(chan *coordinatorOverrideState, 2)

	// similarly, upgradeDetailsChan is a buffered channel as well.
	upgradeDetailsChan := make(chan *details.Details, 2)

	// Create a manager that will allow upgrade attempts but return a failure
	// from Upgrade itself (success requires testing ReExec and we aren't
	// quite ready to do that yet).
	upgradeMgr := &fakeUpgradeManager{
		upgradeable: true,
		upgradeErr:  errors.New("failed upgrade"),
	}

	coord := &Coordinator{
		stateBroadcaster:   broadcaster.New(State{}, 0, 0),
		overrideStateChan:  overrideStateChan,
		upgradeDetailsChan: upgradeDetailsChan,
		upgradeMgr:         upgradeMgr,
		logger:             logp.NewLogger("testing"),
		isManaged:          false,
	}

	action := &fleetapi.ActionMigrate{}

	backoffFactory := func(done <-chan struct{}) backoff.Backoff {
		return backoff.NewExpBackoff(done, 30*time.Millisecond, 2*time.Second)
	}

	err := coord.Migrate(ctx, action, backoffFactory, nil)
	require.ErrorIs(t, err, ErrNotManaged)
}

func TestCoordinator_ContainerAgent_SkipsMigrate(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	// overrideStateChan has buffer 2 so we can run on a single goroutine,
	// since a successful upgrade sets the override state twice.
	overrideStateChan := make(chan *coordinatorOverrideState, 2)

	// similarly, upgradeDetailsChan is a buffered channel as well.
	upgradeDetailsChan := make(chan *details.Details, 2)

	// Create a manager that will allow upgrade attempts but return a failure
	// from Upgrade itself (success requires testing ReExec and we aren't
	// quite ready to do that yet).
	upgradeMgr := &fakeUpgradeManager{
		upgradeable: true,
		upgradeErr:  errors.New("failed upgrade"),
	}

	platformSpecs, _ := pkgcomponent.NewRuntimeSpecs(pkgcomponent.PlatformDetail{
		Platform:                     pkgcomponent.Platform{OS: pkgcomponent.Container},
		NativeArch:                   "",
		Family:                       "",
		Major:                        0,
		Minor:                        0,
		IsInstalledViaExternalPkgMgr: false,
		User:                         pkgcomponent.UserDetail{},
	}, nil)
	coord := &Coordinator{
		stateBroadcaster:   broadcaster.New(State{}, 0, 0),
		overrideStateChan:  overrideStateChan,
		upgradeDetailsChan: upgradeDetailsChan,
		upgradeMgr:         upgradeMgr,
		logger:             logp.NewLogger("testing"),
		isManaged:          false,
		specs:              platformSpecs,
	}

	action := &fleetapi.ActionMigrate{}

	backoffFactory := func(done <-chan struct{}) backoff.Backoff {
		return backoff.NewExpBackoff(done, 30*time.Millisecond, 2*time.Second)
	}

	err := coord.Migrate(ctx, action, backoffFactory, nil)
	require.ErrorIs(t, err, ErrContainerNotSupported)
}

func TestCoordinator_FleetServer_SkipsMigration(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	// overrideStateChan has buffer 2 so we can run on a single goroutine,
	// since a successful upgrade sets the override state twice.
	overrideStateChan := make(chan *coordinatorOverrideState, 2)

	// similarly, upgradeDetailsChan is a buffered channel as well.
	upgradeDetailsChan := make(chan *details.Details, 2)

	// Create a manager that will allow upgrade attempts but return a failure
	// from Upgrade itself (success requires testing ReExec and we aren't
	// quite ready to do that yet).
	upgradeMgr := &fakeUpgradeManager{
		upgradeable: true,
		upgradeErr:  errors.New("failed upgrade"),
	}

	coord := &Coordinator{
		stateBroadcaster:   broadcaster.New(State{}, 0, 0),
		overrideStateChan:  overrideStateChan,
		upgradeDetailsChan: upgradeDetailsChan,
		upgradeMgr:         upgradeMgr,
		logger:             logp.NewLogger("testing"),
		// is managed so we proceed with migration
		isManaged: true,
	}

	// is fleet server
	coord.state.Components = append(coord.state.Components, runtime.ComponentComponentState{
		Component: pkgcomponent.Component{
			InputType: fleetServer,
		},
	})

	action := &fleetapi.ActionMigrate{}

	backoffFactory := func(done <-chan struct{}) backoff.Backoff {
		return backoff.NewExpBackoff(done, 30*time.Millisecond, 2*time.Second)
	}

	err := coord.Migrate(ctx, action, backoffFactory, nil)
	require.ErrorIs(t, err, ErrFleetServer)
}

func TestCoordinator_InitiatesMigration(t *testing.T) {

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmpConfig := t.TempDir()
	pathstest.SetConfig(t, tmpConfig)
	agentConfigFile := paths.ConfigFile()

	var unenrollCalled bool
	oldFleetServer := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			if strings.Contains(r.URL.Path, "unenroll") {
				unenrollCalled = true
			}

			_, err := w.Write(nil)
			require.NoError(t, err)

		}))
	defer oldFleetServer.Close()

	fleetConfig := configuration.DefaultFleetAgentConfig()
	fleetConfig.Enabled = true
	fleetConfig.AccessAPIKey = "access-api-key"
	fleetConfig.Info.ID = "agent.id"
	fleetConfig.Client.Host = oldFleetServer.URL
	fleetConfig.Client.Hosts = []string{oldFleetServer.URL}

	agentConfig := &configuration.Configuration{
		Fleet: fleetConfig,
		Settings: &configuration.SettingsConfig{
			ID: "agent.id",
		},
	}

	rawAgentConfig := &configuration.Configuration{
		Fleet: &configuration.FleetAgentConfig{
			Enabled: true,
		},
		Settings: &configuration.SettingsConfig{
			ID: "agent.id",
		},
	}

	rawAgentConfigData, err := yaml.Marshal(rawAgentConfig)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(agentConfigFile, rawAgentConfigData, 0644))

	// setup secret normally previously created by enroll
	err = secret.CreateAgentSecret(ctx,
		vault.WithUnprivileged(true),
		vault.WithVaultPath(paths.AgentVaultPath()),
	)
	require.NoError(t, err)

	store, err := storage.NewEncryptedDiskStore(ctx, paths.AgentConfigFile(),
		storage.WithUnprivileged(true),
		storage.WithVaultPath(paths.AgentVaultPath()),
	)
	require.NoError(t, err)

	fleetAgentConfigData, err := yaml.Marshal(agentConfig)
	require.NoError(t, err)
	require.NoError(t, store.Save(bytes.NewReader(fleetAgentConfigData)))

	// overrideStateChan has buffer 2 so we can run on a single goroutine,
	// since a successful upgrade sets the override state twice.
	overrideStateChan := make(chan *coordinatorOverrideState, 2)

	// similarly, upgradeDetailsChan is a buffered channel as well.
	upgradeDetailsChan := make(chan *details.Details, 2)

	// Create a manager that will allow upgrade attempts but return a failure
	// from Upgrade itself (success requires testing ReExec and we aren't
	// quite ready to do that yet).
	upgradeMgr := &fakeUpgradeManager{
		upgradeable: true,
		upgradeErr:  errors.New("failed upgrade"),
	}

	acker := &fakeActionAcker{}

	acker.On("Ack", mock.Anything, mock.Anything).Return(nil)
	acker.On("Commit", mock.Anything).Return(nil)

	agentInfo, err := info.NewAgentInfo(ctx, false)
	require.NoError(t, err)
	coord := &Coordinator{
		stateBroadcaster:   broadcaster.New(State{}, 0, 0),
		overrideStateChan:  overrideStateChan,
		upgradeDetailsChan: upgradeDetailsChan,
		upgradeMgr:         upgradeMgr,
		logger:             logp.NewLogger("testing"),
		// is managed so we proceed with migration
		isManaged:  true,
		fleetAcker: acker,
		agentInfo:  agentInfo,
	}

	coord.state.Components = append(coord.state.Components, runtime.ComponentComponentState{
		Component: pkgcomponent.Component{
			InputType: "not-a-fleet-server",
		},
	})

	newFleetServer := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			if strings.Contains(r.URL.Path, "status") {
				_, err := w.Write(nil)
				require.NoError(t, err)
				return
			}

			body := []byte(`{
	  "action": "created",
	  "item": {
	    "id": "a4937110-e53e-11e9-934f-47a8e38a522c",
	    "active": true,
	    "policy_id": "default",
	    "type": "PERMANENT",
	    "enrolled_at": "2019-10-02T18:01:22.337Z",
	    "user_provided_metadata": {},
	    "local_metadata": {},
	    "actions": [],
	    "access_api_key": "API_KEY"
	  }
	}`)
			_, err := w.Write(body)
			require.NoError(t, err)

		}))
	defer newFleetServer.Close()

	action := &fleetapi.ActionMigrate{
		Data: fleetapi.ActionMigrateData{
			TargetURI:       newFleetServer.URL,
			EnrollmentToken: "token",
			Settings:        json.RawMessage(`{"insecure":true}`),
		},
		ActionID:   "migrate-id",
		ActionType: "MIGRATE",
	}

	backoffFactory := func(done <-chan struct{}) backoff.Backoff {
		return backoff.NewExpBackoff(done, 30*time.Millisecond, 2*time.Second)
	}

	err = coord.Migrate(ctx, action, backoffFactory, nil)
	require.NoError(t, err)

	acker.AssertCalled(t, "Ack", mock.Anything, action)
	acker.AssertCalled(t, "Commit", mock.Anything)
	require.True(t, unenrollCalled)
}

func TestCoordinator_InvalidComponentRevertsMigration(t *testing.T) {

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmpConfig := t.TempDir()
	pathstest.SetConfig(t, tmpConfig)
	agentConfigFile := paths.ConfigFile()

	var unenrollCalled bool
	oldFleetServer := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			if strings.Contains(r.URL.Path, "unenroll") {
				unenrollCalled = true
			}

			_, err := w.Write(nil)
			require.NoError(t, err)

		}))
	defer oldFleetServer.Close()

	fleetConfig := configuration.DefaultFleetAgentConfig()
	fleetConfig.Enabled = true
	fleetConfig.AccessAPIKey = "access-api-key"
	fleetConfig.Info.ID = "agent.id"
	fleetConfig.Client.Host = oldFleetServer.URL
	fleetConfig.Client.Hosts = []string{oldFleetServer.URL}

	agentConfig := &configuration.Configuration{
		Fleet: fleetConfig,
		Settings: &configuration.SettingsConfig{
			ID: "agent.id",
		},
	}

	rawAgentConfig := &configuration.Configuration{
		Fleet: &configuration.FleetAgentConfig{
			Enabled: true,
		},
		Settings: &configuration.SettingsConfig{
			ID: "agent.id",
		},
	}

	rawAgentConfigData, err := yaml.Marshal(rawAgentConfig)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(agentConfigFile, rawAgentConfigData, 0644))

	// setup secret normally previously created by enroll
	err = secret.CreateAgentSecret(ctx,
		vault.WithUnprivileged(true),
		vault.WithVaultPath(paths.AgentVaultPath()),
	)
	require.NoError(t, err)

	store, err := storage.NewEncryptedDiskStore(ctx, paths.AgentConfigFile(),
		storage.WithUnprivileged(true),
		storage.WithVaultPath(paths.AgentVaultPath()),
	)
	require.NoError(t, err)

	fleetAgentConfigData, err := yaml.Marshal(agentConfig)
	require.NoError(t, err)
	require.NoError(t, store.Save(bytes.NewReader(fleetAgentConfigData)))

	// overrideStateChan has buffer 2 so we can run on a single goroutine,
	// since a successful upgrade sets the override state twice.
	overrideStateChan := make(chan *coordinatorOverrideState, 2)

	// similarly, upgradeDetailsChan is a buffered channel as well.
	upgradeDetailsChan := make(chan *details.Details, 2)

	// Create a manager that will allow upgrade attempts but return a failure
	// from Upgrade itself (success requires testing ReExec and we aren't
	// quite ready to do that yet).
	upgradeMgr := &fakeUpgradeManager{
		upgradeable: true,
		upgradeErr:  errors.New("failed upgrade"),
	}

	acker := &fakeActionAcker{}

	acker.On("Ack", mock.Anything, mock.Anything).Return(nil)
	acker.On("Commit", mock.Anything).Return(nil)

	agentInfo, err := info.NewAgentInfo(ctx, false)
	require.NoError(t, err)
	coord := &Coordinator{
		stateBroadcaster:   broadcaster.New(State{}, 0, 0),
		overrideStateChan:  overrideStateChan,
		upgradeDetailsChan: upgradeDetailsChan,
		upgradeMgr:         upgradeMgr,
		logger:             logp.NewLogger("testing"),
		// is managed so we proceed with migration
		isManaged:  true,
		fleetAcker: acker,
		agentInfo:  agentInfo,
	}

	coord.state.Components = append(coord.state.Components, runtime.ComponentComponentState{
		Component: pkgcomponent.Component{
			InputType: "not-a-fleet-server",
		},
	})

	newFleetServer := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			if strings.Contains(r.URL.Path, "status") {
				_, err := w.Write(nil)
				require.NoError(t, err)
				return
			}

			body := []byte(`{
	  "action": "created",
	  "item": {
	    "id": "a4937110-e53e-11e9-934f-47a8e38a522c",
	    "active": true,
	    "policy_id": "default",
	    "type": "PERMANENT",
	    "enrolled_at": "2019-10-02T18:01:22.337Z",
	    "user_provided_metadata": {},
	    "local_metadata": {},
	    "actions": [],
	    "access_api_key": "API_KEY"
	  }
	}`)
			_, err := w.Write(body)
			require.NoError(t, err)

		}))
	defer newFleetServer.Close()

	action := &fleetapi.ActionMigrate{
		Data: fleetapi.ActionMigrateData{
			TargetURI:       newFleetServer.URL,
			EnrollmentToken: "token",
			Settings:        json.RawMessage(`{"insecure":true}`),
		},
		ActionID:   "migrate-id",
		ActionType: "MIGRATE",
	}

	backoffFactory := func(done <-chan struct{}) backoff.Backoff {
		return backoff.NewExpBackoff(done, 30*time.Millisecond, 2*time.Second)
	}

	failingComponentNotify := func(_ context.Context, _ *fleetapi.ActionMigrate) error {
		return fmt.Errorf("failed to notify")
	}

	err = coord.Migrate(ctx, action, backoffFactory, failingComponentNotify)
	require.Error(t, err)

	acker.AssertNumberOfCalls(t, "Ack", 0)
	acker.AssertNotCalled(t, "Commit", 0)
	require.False(t, unenrollCalled)
}

// Returns an empty but non-nil set of transpiler variables for testing
// (Coordinator will only regenerate its component model when it has non-nil
// vars).
func emptyVars(t *testing.T) []*transpiler.Vars {
	vars, err := transpiler.NewVars("", map[string]interface{}{}, nil, "")
	require.NoError(t, err, "Vars creation must succeed")
	return []*transpiler.Vars{vars}
}

func emptyAST(t *testing.T) *transpiler.AST {
	ast, err := transpiler.NewAST(nil)
	require.NoError(t, err, "AST creation must succeed")
	return ast
}

type fakeMonitoringServer struct {
	startTriggered bool
	stopTriggered  bool
	isRunning      bool
}

func (fs *fakeMonitoringServer) Start() {
	fs.startTriggered = true
	fs.isRunning = true
}

func (fs *fakeMonitoringServer) Stop() error {
	fs.stopTriggered = true
	fs.isRunning = false
	return nil
}

func (fs *fakeMonitoringServer) Reset() {
	fs.stopTriggered = false
	fs.startTriggered = false
}

func (fs *fakeMonitoringServer) Addr() net.Addr {
	return nil
}

func TestMergeFleetConfig(t *testing.T) {
	testutils.InitStorage(t)

	cfg := map[string]interface{}{
		"fleet": map[string]interface{}{
			"enabled":        true,
			"kibana":         map[string]interface{}{"host": "demo"},
			"access_api_key": "123",
		},
		"agent": map[string]interface{}{
			"grpc": map[string]interface{}{
				"port": uint16(6790),
			},
		},
	}

	path := paths.AgentConfigFile()
	store, err := storage.NewEncryptedDiskStore(t.Context(), path)
	require.NoError(t, err)

	rawConfig := config.MustNewConfigFrom(cfg)
	conf, err := mergeFleetConfig(t.Context(), rawConfig, store)
	require.NoError(t, err)
	assert.NotNil(t, conf)
	assert.Equal(t, conf.Fleet.Enabled, cfg["fleet"].(map[string]interface{})["enabled"])
	assert.Equal(t, conf.Fleet.AccessAPIKey, cfg["fleet"].(map[string]interface{})["access_api_key"])
	assert.Equal(t, conf.Settings.GRPC.Port, cfg["agent"].(map[string]interface{})["grpc"].(map[string]interface{})["port"].(uint16))
}

func TestComputeEnrollOptions(t *testing.T) {
	testutils.InitStorage(t)
	tmp := t.TempDir()

	storePath := filepath.Join(tmp, "fleet.enc")
	cfgPath := filepath.Join(tmp, "elastic-agent.yml")

	cfg := map[string]interface{}{
		"fleet": map[string]interface{}{
			"enabled":        true,
			"access_api_key": "123",
		},
		"agent": map[string]interface{}{
			"grpc": map[string]interface{}{
				"port": uint16(6790),
			},
		},
	}

	rawAgentConfigData, err := yaml.Marshal(cfg)
	require.NoError(t, err)

	require.NoError(t, os.WriteFile(cfgPath, rawAgentConfigData, 0644))

	store, err := storage.NewEncryptedDiskStore(t.Context(), storePath)
	require.NoError(t, err)

	fleetConfig := `fleet:
  hosts: [localhost:1234]
  ssl:
    ca_sha256: ["sha1", "sha2"]
    verification_mode: none
  proxy_url: http://proxy.example.com:8080
  proxy_disable: false
  proxy_headers:
    Proxy-Authorization: "Bearer token"
    Custom-Header: "custom-value"
  enrollment_token: enrollment-token-123
  force: true
  insecure: true
  agent:
    id: test-agent-id
`
	require.NoError(t, store.Save(bytes.NewReader([]byte(fleetConfig))))

	options, err := computeEnrollOptions(t.Context(), cfgPath, storePath)
	require.NoError(t, err)

	require.NoError(t, err)
	assert.NotNil(t, options)

	assert.Equal(t, "123", options.EnrollAPIKey, "EnrollAPIKey mismatch")
	assert.Equal(t, "http://localhost:1234", options.URL, "URL mismatch")

	assert.Equal(t, []string{"sha1", "sha2"}, options.CASha256, "CASha256 mismatch")
	assert.Equal(t, true, options.Insecure, "Insecure mismatch")
	assert.Equal(t, "test-agent-id", options.ID, "ID mismatch")
	assert.Equal(t, "http://proxy.example.com:8080", options.ProxyURL, "ProxyURL mismatch")
	assert.Equal(t, false, options.ProxyDisabled, "ProxyDisabled mismatch")
	expectedProxyHeaders := map[string]string{
		"Proxy-Authorization": "Bearer token",
		"Custom-Header":       "custom-value",
	}
	assert.Equal(t, expectedProxyHeaders, options.ProxyHeaders, "ProxyHeaders mismatch")
}

func TestHasEndpoint(t *testing.T) {
	testCases := []struct {
		name     string
		state    State
		expected bool
	}{
		{
			"endpoint",
			State{
				Components: []runtime.ComponentComponentState{
					{
						Component: pkgcomponent.Component{
							InputType: endpoint,
						},
					},
				},
			},
			true,
		},
		{
			"no endpoint",
			State{
				Components: []runtime.ComponentComponentState{
					{
						Component: pkgcomponent.Component{
							InputType: "not endpoint",
						},
					},
				},
			},
			false,
		},

		{
			"no component",
			State{
				Components: []runtime.ComponentComponentState{},
			},
			false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			c := &Coordinator{
				state: tc.state,
			}

			result := c.HasEndpoint()
			assert.Equal(t, tc.expected, result, "HasEndpoint result mismatch")
		})
	}
}

type mockUpgradeManager struct {
	upgradeErr error
}

func (m *mockUpgradeManager) Upgradeable() bool {
	return true
}

func (m *mockUpgradeManager) Reload(cfg *config.Config) error {
	return nil
}

func (m *mockUpgradeManager) Upgrade(ctx context.Context, version string, rollback bool, sources []string, action *fleetapi.ActionUpgrade, details *details.Details, skipVerifyOverride bool, skipDefaultPgp bool, pgpBytes []string, opts ...upgrade.Option) (_ reexec.ShutdownCallbackFn, err error) {
	return nil, m.upgradeErr
}

func (m *mockUpgradeManager) Ack(ctx context.Context, acker acker.Acker) error {
	return nil
}

func (m *mockUpgradeManager) AckAction(ctx context.Context, acker acker.Acker, action fleetapi.Action) error {
	return nil
}

func (m *mockUpgradeManager) MarkerWatcher() upgrade.MarkerWatcher {
	return nil
}

func TestCoordinator_Upgrade_InsufficientDiskSpaceError(t *testing.T) {
	diskSpaceLowErr := upgradeErrors.DiskSpaceLowError{
		"need 1 GB at /data",
		"need 500 MB at /downloads",
	}
	testCases := []struct {
		name        string
		upgradeErr  error
		expectedErr error
	}{
		{
			name:        "disk space low joined with os error",
			upgradeErr:  fmt.Errorf("wrapped: %w", errors.Join(upgradeErrors.OS_DiskSpaceErrors[0], diskSpaceLowErr)),
			expectedErr: diskSpaceLowErr,
		},
		{
			name:        "disk space low",
			upgradeErr:  fmt.Errorf("wrapped: %w", diskSpaceLowErr),
			expectedErr: diskSpaceLowErr,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			log, _ := loggertest.New("coordinator-insufficient-disk-space-test")

			mockUpgradeManager := &mockUpgradeManager{
				upgradeErr: tc.upgradeErr,
			}

			initialState := State{
				CoordinatorState:   agentclient.Healthy,
				CoordinatorMessage: "Running",
			}

			coord := &Coordinator{
				state:              initialState,
				logger:             log,
				upgradeMgr:         mockUpgradeManager,
				stateBroadcaster:   broadcaster.New(initialState, 64, 32),
				overrideStateChan:  make(chan *coordinatorOverrideState),
				upgradeDetailsChan: make(chan *details.Details),
			}

			wg := sync.WaitGroup{}
			wg.Add(2)

			overrideStates := []agentclient.State{}
			go func() {
				state1 := <-coord.overrideStateChan
				overrideStates = append(overrideStates, state1.state)

				state2 := <-coord.overrideStateChan
				if state2 != nil {
					overrideStates = append(overrideStates, state2.state)
				}

				wg.Done()
			}()

			upgradeDetails := []*details.Details{}
			go func() {
				upgradeDetails = append(upgradeDetails, <-coord.upgradeDetailsChan)
				upgradeDetails = append(upgradeDetails, <-coord.upgradeDetailsChan)
				wg.Done()
			}()

			err := coord.Upgrade(t.Context(), "", nil, nil)
			require.Error(t, err)
			require.Equal(t, tc.expectedErr, err)

			wg.Wait()

			require.Equal(t, []agentclient.State{agentclient.Upgrading}, overrideStates)

			require.Equal(t, []*details.Details{
				{
					TargetVersion: "",
					State:         details.StateRequested,
					ActionID:      "",
				},
				{
					TargetVersion: "",
					State:         details.StateFailed,
					Metadata: details.Metadata{
						FailedState: details.StateRequested,
						ErrorMsg:    tc.expectedErr.Error(),
					},
				},
			}, upgradeDetails)
		})
	}
}

func TestMaybeOverrideRuntimeForComponent(t *testing.T) {
	logger := logp.NewLogger("testing")

	// otelSupportedComponent returns a minimal component that passes
	// VerifyComponentIsOtelSupported so the dynamic-inputs logic can be
	// exercised independently.
	otelSupportedComponent := func(dynamic bool) pkgcomponent.Component {
		return pkgcomponent.Component{
			ID:             "test-component",
			RuntimeManager: pkgcomponent.OtelRuntimeManager,
			Dynamic:        dynamic,
			OutputType:     "elasticsearch",
			Units: []pkgcomponent.Unit{
				{
					ID:   "test-unit",
					Type: client.UnitTypeOutput,
					Config: &proto.UnitExpectedConfig{
						Type: "elasticsearch",
					},
				},
			},
		}
	}

	t.Run("no change when DynamicInputs is empty", func(t *testing.T) {
		runtimeCfg := &pkgcomponent.RuntimeConfig{}
		comp := otelSupportedComponent(true)
		maybeOverrideRuntimeForComponent(logger, runtimeCfg, &comp)
		assert.Equal(t, pkgcomponent.OtelRuntimeManager, comp.RuntimeManager)
	})

	t.Run("no change when component is not dynamic", func(t *testing.T) {
		runtimeCfg := &pkgcomponent.RuntimeConfig{
			DynamicInputs: pkgcomponent.DynamicInputsConfig{
				Default: string(pkgcomponent.ProcessRuntimeManager),
			},
		}
		comp := otelSupportedComponent(false)
		maybeOverrideRuntimeForComponent(logger, runtimeCfg, &comp)
		assert.Equal(t, pkgcomponent.OtelRuntimeManager, comp.RuntimeManager)
	})

	t.Run("dynamic component switches to the configured runtime", func(t *testing.T) {
		runtimeCfg := &pkgcomponent.RuntimeConfig{
			DynamicInputs: pkgcomponent.DynamicInputsConfig{
				Default: string(pkgcomponent.ProcessRuntimeManager),
			},
		}
		comp := otelSupportedComponent(true)
		maybeOverrideRuntimeForComponent(logger, runtimeCfg, &comp)
		assert.Equal(t, pkgcomponent.ProcessRuntimeManager, comp.RuntimeManager)
	})

	t.Run("per beat and per input type overrides are honored", func(t *testing.T) {
		runtimeCfg := &pkgcomponent.RuntimeConfig{
			DynamicInputs: pkgcomponent.DynamicInputsConfig{
				Default: string(pkgcomponent.ProcessRuntimeManager),
				Filebeat: pkgcomponent.BeatRuntimeConfig{
					// the input type override keeps this component on the otel runtime
					InputType: map[string]string{"filestream": string(pkgcomponent.OtelRuntimeManager)},
				},
			},
		}

		filestream := otelSupportedComponent(true)
		filestream.InputSpec = &pkgcomponent.InputRuntimeSpec{BinaryName: "filebeat"}
		filestream.InputType = "filestream"
		maybeOverrideRuntimeForComponent(logger, runtimeCfg, &filestream)
		assert.Equal(t, pkgcomponent.OtelRuntimeManager, filestream.RuntimeManager)

		// another filebeat input type falls back to the global default
		logInput := otelSupportedComponent(true)
		logInput.InputSpec = &pkgcomponent.InputRuntimeSpec{BinaryName: "filebeat"}
		logInput.InputType = "log"
		maybeOverrideRuntimeForComponent(logger, runtimeCfg, &logInput)
		assert.Equal(t, pkgcomponent.ProcessRuntimeManager, logInput.RuntimeManager)
	})

	t.Run("default configuration leaves dynamic otel components on otel runtime", func(t *testing.T) {
		runtimeCfg := pkgcomponent.DefaultRuntimeConfig()
		comp := otelSupportedComponent(true)
		maybeOverrideRuntimeForComponent(logger, runtimeCfg, &comp)
		assert.Equal(t, pkgcomponent.OtelRuntimeManager, comp.RuntimeManager)
	})
}

func TestGetDynamicInputs(t *testing.T) {
	log, _ := loggertest.New("get-dynamic-inputs")

	t.Run("returns empty map when renderedInputs is nil", func(t *testing.T) {
		result := getDynamicInputs(log, nil, nil)
		assert.NotNil(t, result)
		assert.Empty(t, result)
	})

	t.Run("returns empty map when renderedInputs is empty", func(t *testing.T) {
		result := getDynamicInputs(log, map[string]transpiler.RenderedInputInfo{}, nil)
		assert.NotNil(t, result)
		assert.Empty(t, result)
	})

	t.Run("identifies inputs with dynamic provider variables", func(t *testing.T) {
		// The `local_dynamic` provider is registered via import side effect above
		renderedInputs := map[string]transpiler.RenderedInputInfo{
			// no dynamic provider
			"static-input": {DynamicProvider: ""},
			// uses local_dynamic provider
			"dynamic-input": {DynamicProvider: "local_dynamic", ProviderVars: []string{"local_dynamic.id"}},
		}
		result := getDynamicInputs(log, renderedInputs, nil)
		assert.NotNil(t, result)
		// The static-input should NOT be marked as dynamic (empty provider)
		assert.False(t, result["static-input"], "static-input should not be marked as dynamic")
		// The dynamic-input SHOULD be marked as dynamic because it uses local_dynamic provider
		assert.True(t, result["dynamic-input"], "dynamic-input should be marked as dynamic")
	})

	t.Run("inputs with non-dynamic provider variables are not marked dynamic", func(t *testing.T) {
		// The env provider is a context provider, not a dynamic provider
		renderedInputs := map[string]transpiler.RenderedInputInfo{
			"env-input": {DynamicProvider: "env", ProviderVars: []string{"env.SOME_VAR"}},
		}
		result := getDynamicInputs(log, renderedInputs, nil)
		assert.NotNil(t, result)
		// The env provider is a context provider, not a dynamic provider
		// So this input should NOT be marked as dynamic
		assert.False(t, result["env-input"], "env-input should not be marked as dynamic")
	})

	t.Run("static_variables", func(t *testing.T) {
		tests := map[string]struct {
			providerVars    []string
			staticVariables []string
			wantDynamic     bool
		}{
			"exact match excludes the input": {
				providerVars:    []string{"local_dynamic.group"},
				staticVariables: []string{"local_dynamic.group"},
				wantDynamic:     false,
			},
			"path prefix match excludes the input": {
				providerVars:    []string{"local_dynamic.node.name", "local_dynamic.node.labels.app"},
				staticVariables: []string{"local_dynamic.node"},
				wantDynamic:     false,
			},
			"prefix must end on a path separator": {
				providerVars:    []string{"local_dynamic.nodename"},
				staticVariables: []string{"local_dynamic.node"},
				wantDynamic:     true,
			},
			"a single uncovered variable keeps the input dynamic": {
				providerVars:    []string{"local_dynamic.group", "local_dynamic.id"},
				staticVariables: []string{"local_dynamic.group"},
				wantDynamic:     true,
			},
			"no recorded variables keeps the input dynamic": {
				providerVars:    nil,
				staticVariables: []string{"local_dynamic.group"},
				wantDynamic:     true,
			},
			"empty static_variables keeps the current behavior": {
				providerVars:    []string{"local_dynamic.group"},
				staticVariables: nil,
				wantDynamic:     true,
			},
		}

		for name, tt := range tests {
			t.Run(name, func(t *testing.T) {
				result := getDynamicInputs(log, map[string]transpiler.RenderedInputInfo{
					"input-1": {DynamicProvider: "local_dynamic", ProviderVars: tt.providerVars},
				}, tt.staticVariables)
				assert.Equal(t, tt.wantDynamic, result["input-1"])
			})
		}
	})
}

type recordingReExecManager struct {
	called bool
}

func (r *recordingReExecManager) ReExec(_ reexec.ShutdownCallbackFn, _ ...string) {
	r.called = true
}

func TestCoordinator_Restart(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	action := &fleetapi.ActionRestart{ActionID: "r1", ActionType: fleetapi.ActionTypeRestart}

	t.Run("not restartable returns ErrNotRestartable and does not re-exec", func(t *testing.T) {
		reexecMgr := &recordingReExecManager{}
		coord := &Coordinator{
			// buffered so SetOverrideState (via ReExec) never blocks without a run loop
			overrideStateChan: make(chan *coordinatorOverrideState, 2),
			canRestart:        func() bool { return false },
			reexecMgr:         reexecMgr,
			logger:            logp.NewLogger("testing"),
		}

		err := coord.Restart(ctx, action)
		require.ErrorIs(t, err, ErrNotRestartable)
		assert.False(t, reexecMgr.called, "should not re-exec when not restartable")
	})

	t.Run("restartable triggers re-exec and override state", func(t *testing.T) {
		reexecMgr := &recordingReExecManager{}
		coord := &Coordinator{
			overrideStateChan: make(chan *coordinatorOverrideState, 2),
			canRestart:        func() bool { return true },
			reexecMgr:         reexecMgr,
			logger:            logp.NewLogger("testing"),
		}

		err := coord.Restart(ctx, action)
		require.NoError(t, err)
		assert.True(t, reexecMgr.called, "should re-exec when restartable")

		select {
		case os := <-coord.overrideStateChan:
			require.NotNil(t, os, "restart should set an override state")
			assert.Equal(t, agentclient.Stopping, os.state)
		default:
			t.Fatal("expected an override state to be set")
		}
	})

	t.Run("containerized environment returns ErrContainerNotSupported and does not re-exec", func(t *testing.T) {
		reexecMgr := &recordingReExecManager{}
		platformSpecs, _ := pkgcomponent.NewRuntimeSpecs(pkgcomponent.PlatformDetail{
			Platform: pkgcomponent.Platform{OS: pkgcomponent.Container},
		}, nil)
		coord := &Coordinator{
			overrideStateChan: make(chan *coordinatorOverrideState, 2),
			// canRestart would otherwise allow the restart (a containerized agent
			// runs under an init such as tini and appears supervised), so this
			// proves the container guard takes precedence.
			canRestart: func() bool { return true },
			reexecMgr:  reexecMgr,
			specs:      platformSpecs,
			logger:     logp.NewLogger("testing"),
		}

		err := coord.Restart(ctx, action)
		require.ErrorIs(t, err, ErrContainerNotSupported)
		assert.False(t, reexecMgr.called, "should not re-exec in a containerized environment")
	})
}

type fakeCPULimitController struct {
	set     []limits.CPULimit
	updates chan cpulimit.Snapshot
	// run, when set, is called by Run.
	run func(ctx context.Context) error
	// ready is returned by Ready. Like the real controller, Set closes it when the cap is off.
	ready       chan struct{}
	readyClosed bool
}

func (f *fakeCPULimitController) Ready() <-chan struct{} {
	return f.ready
}

func (f *fakeCPULimitController) closeReady() {
	if f.ready != nil && !f.readyClosed {
		f.readyClosed = true
		close(f.ready)
	}
}

func (f *fakeCPULimitController) Run(ctx context.Context) error {
	if f.run != nil {
		return f.run(ctx)
	}
	<-ctx.Done()
	return nil
}

func (f *fakeCPULimitController) Set(l limits.CPULimit) {
	f.set = append(f.set, l)
	if !l.Enabled() {
		f.closeReady()
	}
}

// Snapshot follows the last Set like the real controller: disabled without a cap, and pending with a cap.
func (f *fakeCPULimitController) Snapshot() cpulimit.Snapshot {
	if len(f.set) == 0 || !f.set[len(f.set)-1].Enabled() {
		return cpulimit.Snapshot{State: cpulimit.StateDisabled}
	}
	return cpulimit.Snapshot{State: cpulimit.StatePending, Configured: f.set[len(f.set)-1]}
}

func (f *fakeCPULimitController) Updates() <-chan cpulimit.Snapshot {
	return f.updates
}

func cpuLimitPercent(t *testing.T, percent int) limits.CPULimit {
	var l limits.CPULimit
	require.NoError(t, l.Unpack(int64(percent)))
	return l
}

type failingReloader struct{}

func (failingReloader) Reload(*config.Config) error {
	return errors.New("reload failed")
}

func newCPULimitTestCoordinator(t *testing.T, cpuLimit CPULimitController) *Coordinator {
	log, _ := loggertest.New("")
	ticker := time.NewTicker(time.Second * 30)
	t.Cleanup(ticker.Stop)
	return &Coordinator{
		logger:                     log,
		agentInfo:                  &info.AgentInfo{},
		stateBroadcaster:           broadcaster.New(State{}, 0, 0),
		runtimeMgr:                 &fakeRuntimeManager{},
		otelMgr:                    &fakeOTelManager{},
		cpuLimit:                   cpuLimit,
		currentCfg:                 configuration.DefaultConfiguration(),
		vars:                       emptyVars(t),
		componentPIDTicker:         ticker,
		componentPidRequiresUpdate: &atomic.Bool{},
		secretMarkerFunc:           testSecretMarkerFunc,
	}
}

// newCoordinatorWithCPULimit returns a Coordinator from New with no managers other than cpuLimit.
func newCoordinatorWithCPULimit(t *testing.T, cpuLimit CPULimitController) *Coordinator {
	log, _ := loggertest.New("")
	coord := New(log, configuration.DefaultConfiguration(), logp.InfoLevel, &info.AgentInfo{}, pkgcomponent.RuntimeSpecs{},
		nil, nil, nil, nil, nil, nil, nil, false, nil, nil, nil, nil, cpuLimit)
	t.Cleanup(coord.componentPIDTicker.Stop)
	return coord
}

func TestCoordinatorSetsCPULimitForAcceptedConfig(t *testing.T) {
	ctx := t.Context()
	cpuLimit := &fakeCPULimitController{}
	coord := newCPULimitTestCoordinator(t, cpuLimit)

	require.NoError(t, coord.processConfig(ctx, config.MustNewConfigFrom("agent.limits.cpu: 50")))
	assert.Equal(t, []limits.CPULimit{cpuLimitPercent(t, 50)}, cpuLimit.set)

	// An unchanged value is set again, so the controller checks the quota again.
	require.NoError(t, coord.processConfig(ctx, config.MustNewConfigFrom("agent.limits.cpu: 50")))
	assert.Len(t, cpuLimit.set, 2)

	coord.processVars(ctx, emptyVars(t))
	assert.Len(t, cpuLimit.set, 2, "a vars update must not set the CPU limit")

	require.NoError(t, coord.processConfig(ctx, config.MustNewConfigFrom("")))
	assert.Equal(t, []limits.CPULimit{cpuLimitPercent(t, 50), cpuLimitPercent(t, 50), {}}, cpuLimit.set)

	coord.cpuLimit = nil
	require.NoError(t, coord.processConfig(ctx, config.MustNewConfigFrom("agent.limits.cpu: 50")))
}

func TestCoordinatorDoesNotSetCPULimitForRejectedConfig(t *testing.T) {
	tt := []struct {
		name string
		cfg  string
		// inGenerateAST is true when the config is rejected while the AST is generated.
		inGenerateAST bool
		reloader      configReloader
	}{
		{name: "invalid CPU limit", cfg: "agent.limits.cpu: 101", inGenerateAST: true},
		{name: "CPU limit 0", cfg: "agent.limits.cpu: 0", inGenerateAST: true},
		{name: "failed reload after the limits are parsed", cfg: "agent.limits.cpu: 50", inGenerateAST: true, reloader: failingReloader{}},
		{name: "invalid agent settings after the AST is generated", cfg: "agent.limits.cpu: 50\nagent.logging.level: invalid"},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			cpuLimit := &fakeCPULimitController{}
			coord := newCPULimitTestCoordinator(t, cpuLimit)
			coord.monitoringServerReloader = tc.reloader

			err := coord.processConfig(t.Context(), config.MustNewConfigFrom(tc.cfg))
			require.Error(t, err)
			assert.Equal(t, tc.inGenerateAST, coord.configErr != nil)
			assert.Empty(t, cpuLimit.set)
		})
	}
}

func TestCoordinatorKeepsCPULimitWhenComponentModelFails(t *testing.T) {
	cpuLimit := &fakeCPULimitController{}
	coord := newCPULimitTestCoordinator(t, cpuLimit)
	initialCfg := coord.currentCfg

	// The invalid condition fails the component model after the configuration is accepted.
	err := coord.processConfig(t.Context(), config.MustNewConfigFrom(`
agent.limits.cpu: 50
inputs:
  - type: filestream
    condition: invalidExpression
`))
	require.Error(t, err)
	require.Error(t, coord.componentModelErr)
	assert.NoError(t, coord.configErr)
	assert.NotSame(t, initialCfg, coord.currentCfg, "the configuration must stay accepted")
	assert.Equal(t, []limits.CPULimit{cpuLimitPercent(t, 50)}, cpuLimit.set)
}

// cpuQuotaBackend is a cpulimit.Backend that keeps the quota in memory. Only Remove can fail, with removeErr.
type cpuQuotaBackend struct {
	mu    sync.Mutex
	quota cpulimit.Quota
	// parentCPUs is a quota set on a parent of the Agent's service. 0 means none.
	parentCPUs float64
	removeErr  error
}

func (b *cpuQuotaBackend) setRemoveErr(err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.removeErr = err
}

func (b *cpuQuotaBackend) LogicalCPUs(context.Context) (int, error) {
	return 4, nil
}

func (b *cpuQuotaBackend) Inspect(context.Context) (cpulimit.Inspection, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	effective := b.quota
	if b.parentCPUs > 0 && (b.quota.Kind != cpulimit.QuotaSet || b.parentCPUs < b.quota.CPUs) {
		effective = cpulimit.Quota{Kind: cpulimit.QuotaSet, CPUs: b.parentCPUs}
	}
	return cpulimit.Inspection{Service: b.quota, Effective: effective}, nil
}

func (b *cpuQuotaBackend) Apply(_ context.Context, cpus float64) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.quota = cpulimit.Quota{Kind: cpulimit.QuotaSet, CPUs: cpus}
	return nil
}

func (b *cpuQuotaBackend) Remove(context.Context) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.removeErr != nil {
		return b.removeErr
	}
	b.quota = cpulimit.Quota{Kind: cpulimit.QuotaNone}
	return nil
}

func TestCoordinatorReportsStateOfCPULimitController(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		log, _ := loggertest.New("")
		controller := cpulimit.NewController(log, &cpuQuotaBackend{quota: cpulimit.Quota{Kind: cpulimit.QuotaNone}})
		coord := newCPULimitTestCoordinator(t, controller)
		coord.managerChans.cpuLimitUpdate = controller.Updates()

		ctx, cancel := context.WithCancel(t.Context())
		runDone := make(chan struct{})
		go func() {
			defer close(runDone)
			_ = controller.Run(ctx)
		}()
		defer func() {
			cancel()
			<-runDone
			close(coord.stateBroadcaster.InputChan)
		}()

		require.NoError(t, coord.processConfig(ctx, config.MustNewConfigFrom("agent.limits.cpu: 50")))
		// The controller finishes its check, so the update channel holds the final state.
		synctest.Wait()
		coord.runLoopIteration(ctx)
		synctest.Wait()

		state := coord.State().CPULimit
		require.NotNil(t, state)
		assert.Equal(t, cpulimit.StateApplied, state.State)
		assert.Equal(t, cpulimit.Quota{Kind: cpulimit.QuotaSet, CPUs: 2}, state.ActiveQuota)
		assert.Equal(t, controller.Snapshot(), *state)

		// The controller removes its quota and reports the cap as disabled.
		require.NoError(t, coord.processConfig(ctx, config.MustNewConfigFrom("")))
		synctest.Wait()
		coord.runLoopIteration(ctx)
		synctest.Wait()
		state = coord.State().CPULimit
		require.NotNil(t, state)
		assert.Equal(t, cpulimit.Snapshot{State: cpulimit.StateDisabled}, *state)
	})
}

func TestCoordinatorReportsCPULimitState(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		coord := newCoordinatorWithCPULimit(t, nil)
		assert.Nil(t, coord.State().CPULimit, "nothing about the CPU cap is reported without a controller")
		close(coord.stateBroadcaster.InputChan)

		cpuLimit := &fakeCPULimitController{updates: make(chan cpulimit.Snapshot, 1)}
		coord = newCoordinatorWithCPULimit(t, cpuLimit)
		defer close(coord.stateBroadcaster.InputChan)
		require.NotNil(t, coord.State().CPULimit, "a disabled cap is reported")
		assert.Equal(t, cpulimit.Snapshot{State: cpulimit.StateDisabled}, *coord.State().CPULimit)

		unsupported := cpulimit.Snapshot{State: cpulimit.StateUnsupported, Configured: cpuLimitPercent(t, 50), Reason: "not supported"}
		cpuLimit.updates <- unsupported
		coord.runLoopIteration(t.Context())
		synctest.Wait()
		require.NotNil(t, coord.State().CPULimit)
		assert.Equal(t, unsupported, *coord.State().CPULimit)

		cpuLimit.updates <- cpulimit.Snapshot{State: cpulimit.StateDisabled}
		coord.runLoopIteration(t.Context())
		synctest.Wait()
		require.NotNil(t, coord.State().CPULimit)
		assert.Equal(t, cpulimit.Snapshot{State: cpulimit.StateDisabled}, *coord.State().CPULimit)
	})
}

func TestCoordinatorRunsCPULimitController(t *testing.T) {
	tt := []struct {
		name string
		// early is true when the controller's Run returns before the coordinator stops.
		early  bool
		runErr error
	}{
		{name: "runs until the coordinator stops"},
		{name: "returns early with an error", early: true, runErr: errors.New("run failed")},
		{name: "returns early without an error", early: true},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				started := make(chan context.Context, 1)
				release := make(chan struct{})
				cpuLimit := &fakeCPULimitController{run: func(ctx context.Context) error {
					started <- ctx
					if !tc.early {
						<-ctx.Done()
						<-release
					}
					return tc.runErr
				}}
				coord := newCoordinatorWithCPULimit(t, cpuLimit)

				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				done := make(chan error, 1)
				go func() { done <- coord.Run(ctx) }()

				// The time is fake inside the bubble, so the timeouts below do not slow down the test.
				var runCtx context.Context
				select {
				case runCtx = <-started:
				case <-time.After(time.Minute):
					t.Fatal("the controller was not started")
				}
				require.NoError(t, runCtx.Err(), "the controller must run with a live context")
				synctest.Wait()
				require.True(t, coord.IsActive(time.Second), "the coordinator must keep running")

				cancel()
				synctest.Wait()
				if !tc.early {
					select {
					case err := <-done:
						t.Fatalf("the coordinator stopped before the controller: %v", err)
					default:
					}
					close(release)
				}
				select {
				case err := <-done:
					require.ErrorIs(t, err, context.Canceled)
				case <-time.After(time.Minute):
					t.Fatal("the coordinator did not stop")
				}
			})
		})
	}
}

func TestCoordinatorStopsWhenCPULimitControllerHangs(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		started := make(chan struct{})
		release := make(chan struct{})
		defer close(release)
		cpuLimit := &fakeCPULimitController{run: func(context.Context) error {
			close(started)
			// Run ignores its context, like a stuck operating system call.
			<-release
			return nil
		}}
		coord := newCoordinatorWithCPULimit(t, cpuLimit)

		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		done := make(chan error, 1)
		go func() { done <- coord.Run(ctx) }()
		<-started
		synctest.Wait()

		cancel()
		stoppedAt := time.Now()
		// The time is fake inside the bubble, so the timeout below does not slow down the test.
		select {
		case err := <-done:
			require.ErrorIs(t, err, context.Canceled)
			assert.Equal(t, cpuLimitShutdownTimeout, time.Since(stoppedAt), "the coordinator waits for the controller up to the timeout")
		case <-time.After(time.Hour):
			t.Fatal("the coordinator waited for the controller without a limit")
		}
	})
}

// cpuLimitGate is a Coordinator with a CPU limit controller and specs for a command input (filestream),
// Fleet Server and a service input (endpoint).
type cpuLimitGate struct {
	coord *Coordinator
	// cpuLimit is the controller when it is a fake, and nil otherwise.
	cpuLimit *fakeCPULimitController
	// models holds the sorted component IDs of each model the runtime manager received.
	models [][]string
	// otelUpdates holds each update the OTel manager received.
	otelUpdates []gateOTelUpdate
}

type gateOTelUpdate struct {
	cfg *confmap.Conf
	// componentIDs are the sorted IDs of the components in the update.
	componentIDs []string
}

const (
	gateLogsID     = "filestream-default"
	gateLogsOther  = "filestream-other"
	gateFleetID    = "fleet-server-default"
	gateEndpointID = "endpoint"
)

// newCPULimitGate must be called inside a synctest bubble. cpuLimit may be nil.
func newCPULimitGate(t *testing.T, cpuLimit CPULimitController) *cpuLimitGate {
	pathstest.SetTop(t, t.TempDir())
	platforms := []string{"linux/amd64", "linux/arm64", "darwin/amd64", "darwin/arm64", "windows/amd64", "windows/arm64",
		"container/amd64", "container/arm64"}
	command := func(name string) pkgcomponent.InputRuntimeSpec {
		return pkgcomponent.InputRuntimeSpec{InputType: name, BinaryName: name, Spec: pkgcomponent.InputSpec{
			Name: name, Platforms: platforms, Command: &pkgcomponent.CommandSpec{},
		}}
	}
	endpoint := pkgcomponent.InputRuntimeSpec{InputType: "endpoint", BinaryName: "endpoint-security", Spec: pkgcomponent.InputSpec{
		Name: "endpoint", Platforms: platforms, Service: &pkgcomponent.ServiceSpec{},
	}}
	platform, err := pkgcomponent.LoadPlatformDetail()
	require.NoError(t, err)
	specs, err := pkgcomponent.NewRuntimeSpecs(platform, []pkgcomponent.InputRuntimeSpec{command("filestream"), command("fleet-server"), endpoint})
	require.NoError(t, err)

	g := &cpuLimitGate{}
	g.cpuLimit, _ = cpuLimit.(*fakeCPULimitController)
	log, _ := loggertest.New("")
	ticker := time.NewTicker(24 * time.Hour)
	g.coord = &Coordinator{
		logger:           log,
		agentInfo:        &info.AgentInfo{},
		stateBroadcaster: broadcaster.New(State{}, 0, 0),
		state:            State{CoordinatorState: agentclient.Healthy, CoordinatorMessage: "Running"},
		runtimeMgr: &fakeRuntimeManager{updateCallback: func(comps []pkgcomponent.Component) error {
			ids := []string{}
			for _, comp := range comps {
				ids = append(ids, comp.ID)
			}
			slices.Sort(ids)
			g.models = append(g.models, ids)
			return nil
		}},
		otelMgr: &fakeOTelManager{
			updateCollectorCallback: func(cfg *confmap.Conf) error {
				g.otelUpdates = append(g.otelUpdates, gateOTelUpdate{cfg: cfg, componentIDs: []string{}})
				return nil
			},
			// Update calls this right after updateCollectorCallback, so it fills in the update recorded there.
			updateComponentCallback: func(comps []pkgcomponent.Component) error {
				last := &g.otelUpdates[len(g.otelUpdates)-1]
				for _, comp := range comps {
					last.componentIDs = append(last.componentIDs, comp.ID)
				}
				slices.Sort(last.componentIDs)
				return nil
			},
		},
		cpuLimit:                   cpuLimit,
		currentCfg:                 configuration.DefaultConfiguration(),
		specs:                      specs,
		vars:                       emptyVars(t),
		componentPIDTicker:         ticker,
		componentPidRequiresUpdate: &atomic.Bool{},
		secretMarkerFunc:           testSecretMarkerFunc,
	}
	if cpuLimit != nil {
		g.coord.managerChans.cpuLimitUpdate = cpuLimit.Updates()
		g.coord.managerChans.cpuLimitReady = cpuLimit.Ready()
	}
	t.Cleanup(func() {
		ticker.Stop()
		g.coord.stopCPULimitStartTimer()
		close(g.coord.stateBroadcaster.InputChan)
	})
	return g
}

// gatePolicy returns a policy with the given CPU limit and the given output for the filestream input.
// An empty cpu leaves out the agent.limits section.
func gatePolicy(cpu string, logsOutput string) string {
	cpuLine := ""
	if cpu != "" {
		cpuLine = "agent.limits.cpu: " + cpu
	}
	return fmt.Sprintf(`
%s
outputs:
  default:
    type: elasticsearch
    hosts: [localhost:9200]
  other:
    type: elasticsearch
    hosts: [localhost:9200]
inputs:
  - id: logs
    type: filestream
    use_output: %s
  - id: fleet
    type: fleet-server
    use_output: default
  - id: defend
    type: endpoint
    use_output: default
`, cpuLine, logsOutput)
}

// apply processes gatePolicy(cpu, logsOutput).
func (g *cpuLimitGate) apply(t *testing.T, cpu string, logsOutput string) {
	require.NoError(t, g.coord.processConfig(t.Context(), config.MustNewConfigFrom(gatePolicy(cpu, logsOutput))))
}

func (g *cpuLimitGate) lastModel(t *testing.T) []string {
	require.NotEmpty(t, g.models, "the runtime manager received no model")
	return g.models[len(g.models)-1]
}

func (g *cpuLimitGate) health() (agentclient.State, string) {
	s := g.coord.generateReportableState()
	return s.State, s.Message
}

var (
	gateExempt = []string{gateEndpointID, gateFleetID}
	gateFull   = []string{gateEndpointID, gateLogsID, gateFleetID}
)

const gateWaitingMessage = "Waiting for the CPU limit before starting components"

func TestCPULimitGateHoldsComponentsUntilReady(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		g := newCPULimitGate(t, &fakeCPULimitController{ready: make(chan struct{})})

		g.apply(t, "50", "default")
		assert.Equal(t, [][]string{gateExempt}, g.models, "only exempt components start while the cap is not ready")
		state, msg := g.health()
		assert.Equal(t, agentclient.Starting, state)
		assert.Equal(t, gateWaitingMessage, msg)

		g.cpuLimit.closeReady()
		g.coord.runLoopIteration(t.Context())
		assert.Equal(t, [][]string{gateExempt, gateFull}, g.models, "the full model is sent once on release")
		state, msg = g.health()
		assert.Equal(t, agentclient.Healthy, state)
		assert.Equal(t, "Running", msg)

		g.apply(t, "50", "other")
		assert.Equal(t, []string{gateEndpointID, gateLogsOther, gateFleetID}, g.lastModel(t),
			"a policy change after the release is not held")
		assert.Len(t, g.models, 3)
	})
}

func TestCPULimitGateSendsLatestModelOnRelease(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		g := newCPULimitGate(t, &fakeCPULimitController{ready: make(chan struct{})})

		g.apply(t, "50", "default")
		g.apply(t, "50", "other")
		assert.Equal(t, [][]string{gateExempt, gateExempt}, g.models)

		g.cpuLimit.closeReady()
		g.coord.runLoopIteration(t.Context())
		assert.Equal(t, []string{gateEndpointID, gateLogsOther, gateFleetID}, g.lastModel(t))
	})
}

func TestCPULimitGateReleasesWhenCapTurnedOff(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		g := newCPULimitGate(t, &fakeCPULimitController{ready: make(chan struct{})})

		g.apply(t, "50", "default")
		require.Equal(t, gateExempt, g.lastModel(t))

		// The fake controller closes Ready in Set, like the real one does when the cap is off.
		g.apply(t, "", "default")
		assert.Equal(t, gateFull, g.lastModel(t))
		state, msg := g.health()
		assert.Equal(t, agentclient.Healthy, state)
		assert.Equal(t, "Running", msg)
	})
}

func TestCPULimitGateDoesNotHold(t *testing.T) {
	tt := []struct {
		name     string
		cpuLimit func() CPULimitController
		cpu      string
	}{
		{name: "no cap in the policy", cpu: "", cpuLimit: func() CPULimitController {
			return &fakeCPULimitController{ready: make(chan struct{})}
		}},
		{name: "cap without a value", cpu: "null", cpuLimit: func() CPULimitController {
			return &fakeCPULimitController{ready: make(chan struct{})}
		}},
		{name: "no controller", cpu: "50", cpuLimit: func() CPULimitController { return nil }},
		{name: "ready before the first policy", cpu: "50", cpuLimit: func() CPULimitController {
			// For example the cap is unsupported on this host, or it was turned off before.
			f := &fakeCPULimitController{ready: make(chan struct{})}
			f.closeReady()
			return f
		}},
	}
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				g := newCPULimitGate(t, tc.cpuLimit())

				g.apply(t, tc.cpu, "default")
				assert.Equal(t, [][]string{gateFull}, g.models)
				assert.Nil(t, g.coord.cpuLimitStartTimer)
				state, msg := g.health()
				assert.Equal(t, agentclient.Healthy, state)
				assert.Equal(t, "Running", msg)
			})
		})
	}
}

func TestCPULimitGateDoesNotHoldBeforeFirstSet(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		g := newCPULimitGate(t, &fakeCPULimitController{ready: make(chan struct{})})

		// The invalid log level fails the policy after the AST is set and before the CPU limit is set.
		rejected := config.MustNewConfigFrom(gatePolicy("", "default") + "agent.logging.level: invalid\n")
		require.Error(t, g.coord.processConfig(t.Context(), rejected))
		require.Empty(t, g.cpuLimit.set)

		g.coord.processVars(t.Context(), emptyVars(t))
		assert.Equal(t, [][]string{gateFull}, g.models)

		g.apply(t, "50", "default")
		assert.Equal(t, gateFull, g.lastModel(t), "a cap requested after the components started does not hold them")
		state, msg := g.health()
		assert.Equal(t, agentclient.Healthy, state)
		assert.Equal(t, "Running", msg)
	})
}

func TestCPULimitGateRejectedZeroDoesNotHold(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		g := newCPULimitGate(t, &fakeCPULimitController{ready: make(chan struct{})})

		g.apply(t, "", "default")
		require.Equal(t, [][]string{gateFull}, g.models)

		require.Error(t, g.coord.processConfig(t.Context(), config.MustNewConfigFrom(gatePolicy("0", "default"))))
		assert.Equal(t, [][]string{gateFull}, g.models)
		assert.Nil(t, g.coord.cpuLimitStartTimer)
		assert.Equal(t, []limits.CPULimit{{}}, g.cpuLimit.set, "the rejected policy does not set the CPU limit")
	})
}

func TestCPULimitGateUnsupportedHost(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		log, _ := loggertest.New("")
		controller := cpulimit.NewController(log, cpulimit.NewUnsupportedBackend())
		g := newCPULimitGate(t, controller)

		g.apply(t, "50", "default")
		assert.Equal(t, [][]string{gateExempt}, g.models)

		// The controller starts after the policy, so the first model is always held.
		ctx, cancel := context.WithCancel(t.Context())
		runDone := make(chan struct{})
		go func() {
			defer close(runDone)
			_ = controller.Run(ctx)
		}()
		defer func() {
			cancel()
			<-runDone
		}()

		// The controller reports unsupported and closes Ready. One iteration reads the state, the other the release.
		synctest.Wait()
		g.coord.runLoopIteration(ctx)
		g.coord.runLoopIteration(ctx)
		assert.Equal(t, gateFull, g.lastModel(t))
		reported := g.coord.generateReportableState()
		require.NotNil(t, reported.CPULimit)
		assert.Equal(t, cpulimit.StateUnsupported, reported.CPULimit.State)
		assert.Equal(t, agentclient.Healthy, reported.State)
		assert.Equal(t, "Running", reported.Message)
	})
}

func TestCPULimitGateLowerEffectiveQuota(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		log, _ := loggertest.New("")
		backend := &cpuQuotaBackend{quota: cpulimit.Quota{Kind: cpulimit.QuotaNone}, parentCPUs: 1}
		controller := cpulimit.NewController(log, backend)
		g := newCPULimitGate(t, controller)

		ctx, cancel := context.WithCancel(t.Context())
		runDone := make(chan struct{})
		go func() {
			defer close(runDone)
			_ = controller.Run(ctx)
		}()
		defer func() {
			cancel()
			<-runDone
		}()

		g.apply(t, "50", "default")
		// The controller applies the cap and closes Ready. One iteration reads the state, the other the release.
		synctest.Wait()
		g.coord.runLoopIteration(ctx)
		g.coord.runLoopIteration(ctx)

		assert.Equal(t, gateFull, g.lastModel(t), "a lower quota on a parent does not hold the components")
		reported := g.coord.generateReportableState()
		require.NotNil(t, reported.CPULimit)
		assert.Equal(t, cpulimit.StateApplied, reported.CPULimit.State)
		assert.Equal(t, cpulimit.Quota{Kind: cpulimit.QuotaSet, CPUs: 2}, reported.CPULimit.ActiveQuota)
		assert.Equal(t, cpulimit.Quota{Kind: cpulimit.QuotaSet, CPUs: 1}, reported.CPULimit.EffectiveQuota)
		assert.Equal(t, agentclient.Healthy, reported.State)
		assert.Equal(t, "Running", reported.Message)
	})
}

func TestCPULimitGateFailedRemoval(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		log, _ := loggertest.New("")
		backend := &cpuQuotaBackend{quota: cpulimit.Quota{Kind: cpulimit.QuotaNone}}
		controller := cpulimit.NewController(log, backend)
		g := newCPULimitGate(t, controller)

		ctx, cancel := context.WithCancel(t.Context())
		runDone := make(chan struct{})
		go func() {
			defer close(runDone)
			_ = controller.Run(ctx)
		}()
		defer func() {
			cancel()
			<-runDone
		}()

		g.apply(t, "50", "default")
		// The controller applies the cap and closes Ready. One iteration reads the state, the other the release.
		synctest.Wait()
		g.coord.runLoopIteration(ctx)
		g.coord.runLoopIteration(ctx)
		require.Equal(t, gateFull, g.lastModel(t))
		modelsBefore := len(g.models)

		backend.setRemoveErr(errors.New("remove failed"))
		g.apply(t, "", "default")
		synctest.Wait()
		g.coord.runLoopIteration(ctx)

		assert.Equal(t, gateFull, g.lastModel(t), "the components keep running")
		assert.Len(t, g.models, modelsBefore+1, "the policy change sends one full model")
		assert.False(t, g.coord.cpuLimitHeld)
		assert.Nil(t, g.coord.cpuLimitStartTimer)
		reported := g.coord.generateReportableState()
		require.NotNil(t, reported.CPULimit)
		assert.Equal(t, cpulimit.StateDegraded, reported.CPULimit.State)
		assert.Equal(t, agentclient.Degraded, reported.State)
		assert.Equal(t, removalFailedMessage, reported.Message)

		// The controller retries the removal within a minute.
		backend.setRemoveErr(nil)
		time.Sleep(time.Minute)
		synctest.Wait()
		g.coord.runLoopIteration(ctx)

		reported = g.coord.generateReportableState()
		require.NotNil(t, reported.CPULimit)
		assert.Equal(t, cpulimit.Snapshot{State: cpulimit.StateDisabled}, *reported.CPULimit)
		assert.Equal(t, agentclient.Healthy, reported.State)
		assert.Equal(t, "Running", reported.Message)
		assert.Equal(t, gateFull, g.lastModel(t))
	})
}

func TestCPULimitGateTimeout(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		g := newCPULimitGate(t, &fakeCPULimitController{ready: make(chan struct{})})
		g.apply(t, "50", "default")
		heldAt := time.Now()

		// The time is fake inside the bubble, so the sleep does not slow down the test.
		time.Sleep(cpuLimitStartTimeout - time.Second)
		state, _ := g.health()
		require.Equal(t, agentclient.Starting, state)
		// A policy change while held does not restart the timer.
		g.apply(t, "50", "other")

		// The iteration waits for the timeout if it did not pass yet.
		g.coord.runLoopIteration(t.Context())
		assert.Equal(t, cpuLimitStartTimeout, time.Since(heldAt), "the timeout counts from the first hold")
		state, msg := g.health()
		assert.Equal(t, agentclient.Failed, state)
		assert.Contains(t, msg, "CPU limit")
		assert.Equal(t, [][]string{gateExempt, gateExempt}, g.models, "the components stay held after the timeout")

		g.cpuLimit.closeReady()
		g.coord.runLoopIteration(t.Context())
		assert.Equal(t, []string{gateEndpointID, gateLogsOther, gateFleetID}, g.lastModel(t))
		state, msg = g.health()
		assert.Equal(t, agentclient.Healthy, state)
		assert.Equal(t, "Running", msg)
	})
}

func TestCPULimitGateTimerNeedsPolicy(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		g := newCPULimitGate(t, &fakeCPULimitController{ready: make(chan struct{})})

		time.Sleep(2 * cpuLimitStartTimeout)
		// Without a start timer, the iteration ends at the next component PID tick.
		g.coord.runLoopIteration(t.Context())
		state, msg := g.health()
		assert.Equal(t, agentclient.Healthy, state)
		assert.Equal(t, "Running", msg)
	})
}

func TestCPULimitGateHoldsOTelConfig(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		g := newCPULimitGate(t, &fakeCPULimitController{ready: make(chan struct{})})
		// The filestream input runs in the OTel runtime, so the OTel manager gets a component that the gate holds.
		policy := func(logsOutput string) *config.Config {
			return config.MustNewConfigFrom(fmt.Sprintf(`
agent.limits.cpu: 50
outputs:
  default:
    type: elasticsearch
    hosts: [localhost:9200]
  other:
    type: elasticsearch
    hosts: [localhost:9200]
inputs:
  - id: logs
    type: filestream
    use_output: %s
    _runtime_experimental: otel
  - id: fleet
    type: fleet-server
    use_output: default
receivers:
  nop:
exporters:
  nop:
service:
  pipelines:
    logs:
      receivers: [nop]
      exporters: [nop]
`, logsOutput))
		}
		hasPipeline := func(u gateOTelUpdate) bool {
			return u.cfg != nil && slices.Contains(u.cfg.AllKeys(), "service::pipelines::logs::receivers")
		}

		require.NoError(t, g.coord.processConfig(t.Context(), policy("default")))
		require.NoError(t, g.coord.processConfig(t.Context(), policy("other")))
		require.Len(t, g.otelUpdates, 2)
		for _, u := range g.otelUpdates {
			assert.Nil(t, u.cfg, "the otel config waits for the CPU cap")
			assert.Empty(t, u.componentIDs, "the otel components wait for the CPU cap")
		}
		held := len(g.otelUpdates)

		g.cpuLimit.closeReady()
		g.coord.runLoopIteration(t.Context())
		require.Len(t, g.otelUpdates, held+1, "the release sends one otel update")
		released := g.otelUpdates[held]
		assert.True(t, hasPipeline(released), "the release sends the otel config")
		assert.Equal(t, []string{gateLogsOther}, released.componentIDs, "the release sends the latest otel components")

		require.NoError(t, g.coord.processConfig(t.Context(), policy("default")))
		require.Len(t, g.otelUpdates, held+2)
		after := g.otelUpdates[held+1]
		assert.True(t, hasPipeline(after), "a policy change after the release keeps the otel config")
		assert.Equal(t, []string{gateLogsID}, after.componentIDs)
	})
}

func TestCPULimitGateReadyAndTimeoutAtOnce(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		g := newCPULimitGate(t, &fakeCPULimitController{ready: make(chan struct{})})
		g.apply(t, "50", "default")

		// The time is fake inside the bubble, so the sleep does not slow down the test.
		time.Sleep(cpuLimitStartTimeout)
		g.cpuLimit.closeReady()
		// The run loop can pick the timer although Ready is closed too.
		g.coord.handleCPULimitStartTimeout(t.Context())
		assert.Equal(t, gateFull, g.lastModel(t))
		state, msg := g.health()
		assert.Equal(t, agentclient.Healthy, state)
		assert.Equal(t, "Running", msg)
	})
}
