// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package coordinator

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact"
	"github.com/elastic/elastic-agent/internal/pkg/agent/transpiler"
	"github.com/elastic/elastic-agent/internal/pkg/config"
	"github.com/elastic/elastic-agent/pkg/component"
	"github.com/elastic/elastic-agent/pkg/component/runtime"
	agentclient "github.com/elastic/elastic-agent/pkg/control/v2/client"
	"github.com/elastic/elastic-agent/pkg/utils/broadcaster"
)

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
			State:   agentclient.Healthy,
			Message: "Running",
		},
		stateBroadcaster: &broadcaster.Broadcaster[State]{
			InputChan: stateChan,
		},
		managerChans: managerChans{
			varsManagerError: varsErrorChan,
		},
	}
	// Send an error via the vars manager channel, and let Coordinator update
	varsErrorChan <- errors.New("force error")
	coord.runLoopIteration(ctx)

	// Make sure the new state reflects the error
	select {
	case state := <-stateChan:
		assert.Equal(t, agentclient.Failed, state.State, "expected Failed State")
		assert.Equal(t, "force error", state.Message, "state message should match what was sent")
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
			State:   agentclient.Healthy,
			Message: "Running",
		},
		stateBroadcaster: &broadcaster.Broadcaster[State]{
			InputChan: stateChan,
		},
		managerChans: managerChans{
			runtimeManagerUpdate: runtimeChan,
		},
	}

	unhealthyComponent := runtime.ComponentComponentState{
		Component: component.Component{ID: "test-component-1"},
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
		State:   agentclient.Healthy,
		Message: "Running",
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
	}

	comp1 := runtime.ComponentComponentState{
		Component: component.Component{ID: "test-component-1"},
		State: runtime.ComponentState{
			State:   client.UnitStateStarting,
			Message: "test message",
		},
	}
	comp2 := runtime.ComponentComponentState{
		Component: component.Component{ID: "test-component-2"},
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

	state := coord.stateBroadcaster.Get()
	assert.Equal(t, agentclient.Healthy, state.State, "Starting components should produce healthy Coordinator")
	assert.Equal(t, "Running", state.Message, "Starting components shouldn't affect state message")

	// Set comp2 to failed, but send a healthy comp1 state again, and
	// verify that Coordinator is still Degraded.
	comp2.State.State = client.UnitStateFailed
	runtimeChan <- comp2
	coord.runLoopIteration(ctx)
	runtimeChan <- comp1
	coord.runLoopIteration(ctx)

	state = coord.stateBroadcaster.Get()

	assert.Equal(t, agentclient.Degraded, state.State, "Failed component state should cause degraded Coordinator state")
	assert.Equal(t, "1 or more components/units in a failed state", state.Message, "state message should reflect failed component")

	// Make comp2 healthy again and verify that Coordinator recovers
	comp2.State.State = client.UnitStateHealthy
	runtimeChan <- comp2
	coord.runLoopIteration(ctx)
	state = coord.stateBroadcaster.Get()
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
			State:   agentclient.Healthy,
			Message: "Running",
		},
		stateBroadcaster: &broadcaster.Broadcaster[State]{
			InputChan: stateChan,
		},
		managerChans: managerChans{
			runtimeManagerUpdate: runtimeChan,
		},
	}

	// Create a healthy component with healthy input and output units
	inputKey := runtime.ComponentUnitKey{
		UnitType: client.UnitTypeInput,
		UnitID:   "input-unit-1"}
	outputKey := runtime.ComponentUnitKey{
		UnitType: client.UnitTypeOutput,
		UnitID:   "output-unit-1"}
	comp := runtime.ComponentComponentState{
		Component: component.Component{ID: "test-component-1"},
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
	// Test that an obviously invalid policy sent to Coordinator will call
	// its Fail callback with an appropriate error.
	// Coordinator also sets its own state to Failed on this error, but
	// currently that state will be discarded by the next update, see
	// https://github.com/elastic/elastic-agent/issues/2852. When that
	// issue is fixed we should test that here too.

	// Set a one-second timeout -- nothing here should block, but if it
	// does let's report a failure instead of timing out the test runner.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	logger := logp.NewLogger("testing")

	// Channels have buffer length 1 so we don't have to run on multiple
	// goroutines.
	stateChan := make(chan State, 1)
	configChan := make(chan ConfigChange, 1)
	varsChan := make(chan []*transpiler.Vars, 1)
	coord := &Coordinator{
		logger: logger,
		state: State{
			State:   agentclient.Healthy,
			Message: "Running",
		},
		stateBroadcaster: &broadcaster.Broadcaster[State]{InputChan: stateChan},
		managerChans: managerChans{
			configManagerUpdate: configChan,
			varsManagerUpdate:   varsChan,
		},
		// Policy changes are sent to the upgrade manager, which scans it
		// for updated artifact URIs. We take advantage of this for the
		// test by sending an invalid artifact URI to trigger an error.
		upgradeMgr: upgrade.NewUpgrader(
			logger,
			&artifact.Config{},
			&info.AgentInfo{},
		),
	}

	// Send an empty vars update, since Coordinator won't try to apply a policy
	// change unless it has received valid vars.
	varsChan <- []*transpiler.Vars{{}}
	coord.runLoopIteration(ctx)

	// Setting the vars alone doesn't trigger a state change unless it
	// causes an error, which can't happen until there's a policy to run
	// against. Make sure no new state has arrived.
	select {
	case <-stateChan:
		assert.Fail(t, "Setting empty vars with no policy shouldn't trigger a Coordinator state change")
	default:
	}

	// Send an invalid config update and confirm that Coordinator reports
	// the failure to the config change object.
	cfg := config.MustNewConfigFrom(map[string]interface{}{
		// Give an incorrectly typed value for the artifacts URI, which should
		// cause the policy update to fail in the upgrade manager.
		"agent.download.sourceURI": map[string]interface{}{
			"the problem": "URIs shouldn't have subfields",
		},
	})
	configChange := &configChange{cfg: cfg}
	configChan <- configChange
	coord.runLoopIteration(ctx)

	assert.True(t, configChange.failed, "Policy with invalid field should have reported failed config change")
	assert.Truef(t,
		strings.HasPrefix(configChange.err.Error(),
			"failed to reload upgrade manager configuration"),
		"wrong error message, expected 'failed to reload upgrade manager configuration...' got %v",
		configChange.err.Error())
}

func TestCoordinatorPolicyChangesUpdateRuntimeManager(t *testing.T) {

}

func TestCoordinatorReportsRuntimeManagerPolicyFailure(t *testing.T) {

}

func TestCoordinatorReportsOverrideState(t *testing.T) {

}

func TestCoordinatorAppliesVarsToPolicy(t *testing.T) {
	// Test both initial vars and changing vars after policy is computed
}

func TestPolicyChangeRegeneratesComponentModel(t *testing.T) {

}

func TestCoordinatorInitiatesUpgrade(t *testing.T) {

}
