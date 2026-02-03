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
	"strings"
	"sync"
	"testing"
	"time"

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

	"github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/monitoring/reload"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/reexec"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/secret"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact"
	upgradeErrors "github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact/download/errors"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/details"
	"github.com/elastic/elastic-agent/internal/pkg/agent/configuration"
	"github.com/elastic/elastic-agent/internal/pkg/agent/storage"
	"github.com/elastic/elastic-agent/internal/pkg/agent/transpiler"
	"github.com/elastic/elastic-agent/internal/pkg/agent/vault"
	"github.com/elastic/elastic-agent/internal/pkg/composable"
	_ "github.com/elastic/elastic-agent/internal/pkg/composable/providers/localdynamic"
	"github.com/elastic/elastic-agent/internal/pkg/config"
	"github.com/elastic/elastic-agent/internal/pkg/core/backoff"
	monitoringCfg "github.com/elastic/elastic-agent/internal/pkg/core/monitoring/config"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi"
	"github.com/elastic/elastic-agent/internal/pkg/testutils/fipsutils"
	pkgcomponent "github.com/elastic/elastic-agent/pkg/component"
	"github.com/elastic/elastic-agent/pkg/component/runtime"
	agentclient "github.com/elastic/elastic-agent/pkg/control/v2/client"
	"github.com/elastic/elastic-agent/pkg/core/logger"
	"github.com/elastic/elastic-agent/pkg/core/logger/loggertest"
	"github.com/elastic/elastic-agent/pkg/utils/broadcaster"
)

var testSecretMarkerFunc = func(*logger.Logger, *config.Config) error {
	// no-op secret marker function for testing
	return nil
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
	// in Coordinator.componentGenErr, and reported by Coordinator.State.

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
	// invalid, so its failure should be reported in componentGenErr.
	cfg := config.MustNewConfigFrom(`
inputs:
  - type: filestream
    condition: invalidExpression
`)
	cfgChange := &configChange{cfg: cfg}
	configChan <- cfgChange
	coord.runLoopIteration(ctx)

	require.Error(t, coord.componentGenErr)
	require.Contains(t, coord.componentGenErr.Error(), "rendering inputs failed:")
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

	assert.Error(t, coord.componentGenErr, "Vars update shouldn't affect componentGenErr")
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
	select {
	case state := <-stateChan:
		assert.Equal(t, agentclient.Healthy, state.State, "Valid policy change should produce healthy state")
		assert.Equal(t, state.Message, "Running", "Valid policy change should restore previous state message")
	default:
		assert.Fail(t, "Policy change should cause state update")
	}
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

}

func TestCoordinatorManagesComponentWorkDirs(t *testing.T) {
	// Send a test policy to the Coordinator as a Config Manager update,
	// verify it creates a working directory for the component, keeps that working directory as the component
	// moves to a different runtime, then deletes it after the component is stopped.
	top := paths.Top()
	paths.SetTop(t.TempDir())
	t.Cleanup(func() {
		paths.SetTop(top)
	})

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
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
	err := coord.Upgrade(ctx, "1.2.3", "", nil, WithSkipVerifyOverride(false), WithSkipDefaultPgp(false))
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
	fipsutils.SkipIfFIPSOnly(t, "vault does not use NewGCMWithRandomNonce.")
	cfgPath := paths.Config()
	defer paths.SetConfig(cfgPath)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmpConfig := t.TempDir()
	paths.SetConfig(tmpConfig)
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
	fipsutils.SkipIfFIPSOnly(t, "vault does not use NewGCMWithRandomNonce.")
	cfgPath := paths.Config()
	defer paths.SetConfig(cfgPath)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmpConfig := t.TempDir()
	paths.SetConfig(tmpConfig)
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

func (m *mockUpgradeManager) Upgrade(ctx context.Context, version string, rollback bool, sourceURI string, action *fleetapi.ActionUpgrade, details *details.Details, skipVerifyOverride bool, skipDefaultPgp bool, pgpBytes ...string) (_ reexec.ShutdownCallbackFn, err error) {
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
	log, _ := loggertest.New("coordinator-insufficient-disk-space-test")

	mockUpgradeManager := &mockUpgradeManager{
		upgradeErr: fmt.Errorf("wrapped: %w", upgradeErrors.ErrInsufficientDiskSpace),
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

	err := coord.Upgrade(t.Context(), "", "", nil)
	require.Error(t, err)
	require.Equal(t, err, upgradeErrors.ErrInsufficientDiskSpace)

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
				ErrorMsg:    upgradeErrors.ErrInsufficientDiskSpace.Error(),
			},
		},
	}, upgradeDetails)
}

func TestMaybeOverrideRuntimeForComponent(t *testing.T) {
	logger := logp.NewLogger("testing")

	t.Run("process runtime is not changed", func(t *testing.T) {
		runtimeCfg := &pkgcomponent.RuntimeConfig{
			DynamicInputs: "process",
		}
		comp := pkgcomponent.Component{
			ID:             "test-component",
			RuntimeManager: pkgcomponent.ProcessRuntimeManager,
			Dynamic:        false,
		}
		maybeOverrideRuntimeForComponent(logger, runtimeCfg, &comp)
		assert.Equal(t, pkgcomponent.ProcessRuntimeManager, comp.RuntimeManager, "ProcessRuntimeManager should not be changed")

		// Even if dynamic, ProcessRuntimeManager should stay
		comp.Dynamic = true
		maybeOverrideRuntimeForComponent(logger, runtimeCfg, &comp)
		assert.Equal(t, pkgcomponent.ProcessRuntimeManager, comp.RuntimeManager, "ProcessRuntimeManager should not be changed even when dynamic")
	})

	t.Run("dynamic otel component switches to process runtime when configured", func(t *testing.T) {
		runtimeCfg := &pkgcomponent.RuntimeConfig{
			DynamicInputs: "process",
		}
		comp := pkgcomponent.Component{
			ID:             "test-component",
			RuntimeManager: pkgcomponent.OtelRuntimeManager,
			Dynamic:        true,
		}
		maybeOverrideRuntimeForComponent(logger, runtimeCfg, &comp)
		assert.Equal(t, pkgcomponent.ProcessRuntimeManager, comp.RuntimeManager, "Dynamic OTel component should switch to ProcessRuntimeManager when DynamicInputs is 'process'")
	})

	t.Run("dynamic otel component stays otel when DynamicInputs is empty", func(t *testing.T) {
		runtimeCfg := &pkgcomponent.RuntimeConfig{
			DynamicInputs: "",
		}
		comp := pkgcomponent.Component{
			ID:             "test-component",
			RuntimeManager: pkgcomponent.OtelRuntimeManager,
			Dynamic:        true,
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
		maybeOverrideRuntimeForComponent(logger, runtimeCfg, &comp)
		// When DynamicInputs is empty, dynamic components should NOT be switched
		assert.Equal(t, pkgcomponent.OtelRuntimeManager, comp.RuntimeManager, "Dynamic OTel component should stay as OTel when DynamicInputs is empty")
	})

	t.Run("dynamic otel component stays otel when DynamicInputs is otel", func(t *testing.T) {
		runtimeCfg := &pkgcomponent.RuntimeConfig{
			DynamicInputs: "otel",
		}
		comp := pkgcomponent.Component{
			ID:             "test-component",
			RuntimeManager: pkgcomponent.OtelRuntimeManager,
			Dynamic:        true,
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
		maybeOverrideRuntimeForComponent(logger, runtimeCfg, &comp)
		// When DynamicInputs matches the current runtime, no switch should happen
		assert.Equal(t, pkgcomponent.OtelRuntimeManager, comp.RuntimeManager, "Dynamic OTel component should stay as OTel when DynamicInputs is 'otel'")
	})

	t.Run("non-dynamic otel component stays as otel runtime", func(t *testing.T) {
		runtimeCfg := &pkgcomponent.RuntimeConfig{
			DynamicInputs: "process",
		}
		// This test verifies the component stays as OTel when:
		// - RuntimeManager is OtelRuntimeManager
		// - Dynamic is false
		// - No unsupported config issues (we're not setting any complex output config)
		comp := pkgcomponent.Component{
			ID:             "test-component",
			RuntimeManager: pkgcomponent.OtelRuntimeManager,
			Dynamic:        false,
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
		maybeOverrideRuntimeForComponent(logger, runtimeCfg, &comp)
		// Note: the component may still be switched to ProcessRuntimeManager by
		// VerifyComponentIsOtelSupported if there are other unsupported features
		// For this test, we're just verifying the Dynamic flag check
		// Since there's no error from VerifyComponentIsOtelSupported in this minimal case,
		// the runtime should stay as OTel unless the translate package rejects it
		assert.Equal(t, pkgcomponent.OtelRuntimeManager, comp.RuntimeManager, "Non-dynamic OTel component should stay as OTel even when DynamicInputs is 'process'")
	})
}

func TestGetDynamicInputs(t *testing.T) {
	// Import the kubernetes provider to register "kubernetes" as a dynamic provider
	// This is done via import side effects in the actual application
	_ = composable.Providers

	t.Run("returns empty map when inputToDynamicProvider is nil", func(t *testing.T) {
		result := getDynamicInputs(nil)
		assert.NotNil(t, result)
		assert.Empty(t, result)
	})

	t.Run("returns empty map when inputToDynamicProvider is empty", func(t *testing.T) {
		result := getDynamicInputs(map[string]string{})
		assert.NotNil(t, result)
		assert.Empty(t, result)
	})

	t.Run("identifies inputs with dynamic provider variables", func(t *testing.T) {
		// The `local_dynamic` provider is registered via import side effect above
		inputToDynamicProvider := map[string]string{
			"static-input":  "",              // no dynamic provider
			"dynamic-input": "local_dynamic", // uses local_dynamic provider
		}
		result := getDynamicInputs(inputToDynamicProvider)
		assert.NotNil(t, result)
		// The static-input should NOT be marked as dynamic (empty provider)
		assert.False(t, result["static-input"], "static-input should not be marked as dynamic")
		// The dynamic-input SHOULD be marked as dynamic because it uses local_dynamic provider
		assert.True(t, result["dynamic-input"], "dynamic-input should be marked as dynamic")
	})

	t.Run("inputs with non-dynamic provider variables are not marked dynamic", func(t *testing.T) {
		// The env provider is a context provider, not a dynamic provider
		inputToDynamicProvider := map[string]string{
			"env-input": "env",
		}
		result := getDynamicInputs(inputToDynamicProvider)
		assert.NotNil(t, result)
		// The env provider is a context provider, not a dynamic provider
		// So this input should NOT be marked as dynamic
		assert.False(t, result["env-input"], "env-input should not be marked as dynamic")
	})
}
