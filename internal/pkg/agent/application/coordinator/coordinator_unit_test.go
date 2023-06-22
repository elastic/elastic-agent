// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package coordinator

// This is a companion to coordinator_test.go focusing on the new
// deterministic / channel-based testing model. Over time more of the old
// tests should migrate to this model, and when that progresses far enough
// the two files should be merged, the separation is just to informally
// keep track of migration progress.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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
	cfg := config.MustNewConfigFrom(`
name: "this config is invalid"
agent.download.sourceURI:
  the.problem: "URIs shouldn't have subfields"
`)
	configChange := &configChange{cfg: cfg}
	configChan <- configChange
	coord.runLoopIteration(ctx)

	assert.True(t, configChange.failed, "Policy with invalid field should have reported failed config change")
	assert.Truef(t,
		strings.HasPrefix(configChange.err.Error(),
			"failed to reload upgrade manager configuration"),
		"wrong error message, expected 'failed to reload upgrade manager configuration...' got %v",
		configChange.err.Error())

	select {
	case state := <-stateChan:
		assert.Equal(t, agentclient.Failed, state.State, "Failed policy change should cause Failed coordinator state")
		assert.Equal(t, configChange.err.Error(), state.Message, "Coordinator state should report failed policy change")
	default:
		assert.Fail(t, "Coordinator's state didn't change")
	}
}

func TestCoordinatorPolicyChangeUpdatesRuntimeManager(t *testing.T) {
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
	varsChan := make(chan []*transpiler.Vars, 1)

	// Create a mocked runtime manager that will report the update call
	var updated bool                     // Set by runtime manager callback
	var components []component.Component // Set by runtime manager callback
	runtimeManager := &fakeRuntimeManager{
		updateCallback: func(comp []component.Component) error {
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
		runtimeMgr: runtimeManager,
	}

	// Send an empty vars update, since Coordinator won't try to apply a policy
	// change unless it has received valid vars.
	varsChan <- []*transpiler.Vars{{}}
	coord.runLoopIteration(ctx)

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

	// Make sure the runtime manager received the expected component update.
	// An assert.Equal on the full component model doesn't play nice with
	// the embedded proto structs, so instead we verify the important fields
	// manually (sorry).
	assert.True(t, updated, "Runtime manager should be updated after a policy change")
	require.Equal(t, 1, len(components), "Test policy should generate one component")

	component := components[0]
	assert.Equal(t, "filestream-default", component.ID)
	require.NotNil(t, component.Err, "Input with no spec should produce a component error")
	assert.Equal(t, "input not supported", component.Err.Error(), "Input with no spec should report 'input not supported'")
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

	// Send a new empty config update and make sure the runtime manager
	// receives that as well.
	updated = false
	components = nil
	cfgChange = &configChange{cfg: config.MustNewConfigFrom(nil)}
	configChan <- cfgChange
	coord.runLoopIteration(ctx)
	assert.True(t, cfgChange.acked, "empty policy should be acknowledged")
	assert.True(t, updated, "empty policy should cause runtime manager update")
	assert.Empty(t, components, "empty policy should produce empty component model")
}

func TestCoordinatorReportsRuntimeManagerUpdateFailure(t *testing.T) {
	// Set a one-second timeout -- nothing here should block, but if it
	// does let's report a failure instead of timing out the test runner.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	logger := logp.NewLogger("testing")

	configChan := make(chan ConfigChange, 1)
	varsChan := make(chan []*transpiler.Vars, 1)

	// Create a mocked runtime manager that always reports an error
	runtimeManager := &fakeRuntimeManager{
		updateCallback: func(comp []component.Component) error {
			return fmt.Errorf("update failed for testing reasons")
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
		runtimeMgr: runtimeManager,
	}

	// Send an empty vars update, since Coordinator won't try to apply a policy
	// change unless it has received valid vars.
	varsChan <- []*transpiler.Vars{{}}
	coord.runLoopIteration(ctx)

	// Send an empty policy which should forward an empty component model to
	// the runtime manager (which we have set up to report an error).
	cfg := config.MustNewConfigFrom(nil)
	configChange := &configChange{cfg: cfg}
	configChan <- configChange
	coord.runLoopIteration(ctx)

	// Make sure the failure was reported to the config manager
	assert.True(t, configChange.failed, "Config change should report failure if the runtime manager returns an error")
	require.Error(t, configChange.err, "Config change should get an error if runtime manager update fails")
	assert.Equal(t, "update failed for testing reasons", configChange.err.Error())

	// Make sure the error was reported in Coordinator state.
	// (Note: this reported failure will not be stable, see
	// https://github.com/elastic/elastic-agent/issues/2852)
	state := coord.State()
	assert.Equal(t, agentclient.Failed, state.State, "Failed policy update should cause failed Coordinator")
	assert.Equal(t, "update failed for testing reasons", state.Message, "Failed policy update should be reported in Coordinator state message")
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
	var updated bool                     // Set by runtime manager callback
	var components []component.Component // Set by runtime manager callback
	runtimeManager := &fakeRuntimeManager{
		updateCallback: func(comp []component.Component) error {
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
		runtimeMgr: runtimeManager,
	}

	// Send an empty vars update, since Coordinator won't try to apply a policy
	// change unless it has received valid vars.

	vars, err := transpiler.NewVars("", map[string]interface{}{}, nil)
	require.NoError(t, err, "Vars creation must succeed")

	varsChan <- []*transpiler.Vars{vars}
	coord.runLoopIteration(ctx)

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
	vars, err = transpiler.NewVars("", map[string]interface{}{
		"TEST_VAR": "input-id",
	}, nil)
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
	}, nil)
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
			State:   agentclient.Degraded,
			Message: "Running",
		},
		stateBroadcaster: &broadcaster.Broadcaster[State]{
			InputChan: stateChan,
		},
		overrideStateChan: overrideStateChan,
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

func TestCoordinatorInitiatesUpgrade(t *testing.T) {
	// Set a one-second timeout -- nothing here should block, but if it
	// does let's report a failure instead of timing out the test runner.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	// overrideStateChan has buffer 2 so we can run on a single goroutine,
	// since a successful upgrade sets the override state twice.
	overrideStateChan := make(chan *coordinatorOverrideState, 2)

	// Create a manager that will allow upgrade attempts but return a failure
	// from Upgrade itself (success requires testing ReExec and we aren't
	// quite ready to do that yet).
	upgradeMgr := &fakeUpgradeManager{
		upgradeable: true,
		upgradeErr:  errors.New("failed upgrade"),
	}

	coord := &Coordinator{
		stateBroadcaster:  broadcaster.New(State{}, 0, 0),
		overrideStateChan: overrideStateChan,
		upgradeMgr:        upgradeMgr,
	}

	// Call upgrade and make sure the upgrade manager receives an Upgrade call
	err := coord.Upgrade(ctx, "1.2.3", "", nil, false)
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
