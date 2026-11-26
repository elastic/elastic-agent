// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package coordinator

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/beats/v7/pkg/logp"
	"github.com/elastic/elastic-agent-client/v7/pkg/client"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/cpulimit"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	pkgcomponent "github.com/elastic/elastic-agent/pkg/component"
	"github.com/elastic/elastic-agent/pkg/component/runtime"
	agentclient "github.com/elastic/elastic-agent/pkg/control/v2/client"
	"github.com/elastic/elastic-agent/pkg/utils/broadcaster"
)

func TestApplyComponentState_LateStoppedFromDifferentRuntimeIgnored(t *testing.T) {
	comp1 := pkgcomponent.Component{
		ID:               "filestream-default",
		RuntimeManager:   pkgcomponent.OtelRuntimeManager,
		LastConfiguredAt: time.Now(),
	}
	comp2 := pkgcomponent.Component{
		ID:               "system/metrics-default",
		RuntimeManager:   pkgcomponent.OtelRuntimeManager,
		LastConfiguredAt: time.Now(),
	}
	coord := &Coordinator{
		state: State{
			CoordinatorState:   agentclient.Healthy,
			CoordinatorMessage: "Running",
		},
		stateBroadcaster: broadcaster.New(State{}, 0, 0),
		componentModel: []pkgcomponent.Component{
			comp1,
			comp2,
		},
	}

	filestreamID := "filestream-default"
	metricsID := "system/metrics-default"

	// Both components start under otel runtime and become healthy.
	coord.applyComponentState(runtime.ComponentComponentState{
		Component: comp1,
		State: runtime.ComponentState{
			State:   client.UnitStateHealthy,
			Message: "Healthy",
		},
	})
	coord.applyComponentState(runtime.ComponentComponentState{
		Component: comp2,
		State: runtime.ComponentState{
			State:   client.UnitStateHealthy,
			Message: "Healthy",
		},
	})
	require.Len(t, coord.state.Components, 2)

	// simulate a delay
	// TODO: use synctest once after we upgrade to Go 1.25
	time.Sleep(100 * time.Millisecond)

	// Runtime switch: both components start under the process runtime.
	// The STARTING state is allowed to replace the existing entry even when
	// the RuntimeManager differs.
	comp1New := pkgcomponent.Component{
		ID:               "filestream-default",
		RuntimeManager:   pkgcomponent.ProcessRuntimeManager,
		LastConfiguredAt: time.Now(),
	}
	comp2New := pkgcomponent.Component{
		ID:               "system/metrics-default",
		RuntimeManager:   pkgcomponent.ProcessRuntimeManager,
		LastConfiguredAt: time.Now(),
	}

	coord.applyComponentState(runtime.ComponentComponentState{
		Component: comp1New,
		State: runtime.ComponentState{
			State:   client.UnitStateStarting,
			Message: "Starting",
		},
	})
	coord.applyComponentState(runtime.ComponentComponentState{
		Component: comp2New,
		State: runtime.ComponentState{
			State:   client.UnitStateStarting,
			Message: "Starting",
		},
	})
	require.Len(t, coord.state.Components, 2, "STARTING from a new runtime should replace, not duplicate")
	for _, cs := range coord.state.Components {
		assert.Equal(t, pkgcomponent.ProcessRuntimeManager, cs.Component.RuntimeManager,
			"component %s should now be under process runtime", cs.Component.ID)
		assert.Equal(t, client.UnitStateStarting, cs.State.State)
	}

	// Process runtime components become healthy.
	coord.applyComponentState(runtime.ComponentComponentState{
		Component: comp1New,
		State: runtime.ComponentState{
			State:   client.UnitStateHealthy,
			Message: "Healthy: communicating with pid",
		},
	})
	coord.applyComponentState(runtime.ComponentComponentState{
		Component: comp2New,
		State: runtime.ComponentState{
			State:   client.UnitStateHealthy,
			Message: "Healthy: communicating with pid",
		},
	})
	require.Len(t, coord.state.Components, 2)
	for _, cs := range coord.state.Components {
		assert.Equal(t, client.UnitStateHealthy, cs.State.State,
			"component %s should be healthy", cs.Component.ID)
	}

	// Late STOPPED events arrive from the old otel runtime. This simulates
	// the race where the otel collector takes >3 seconds to stop, so these
	// events arrive after the process runtime is already healthy.
	coord.applyComponentState(runtime.ComponentComponentState{
		Component: comp1,
		State: runtime.ComponentState{
			State: client.UnitStateStopped,
		},
	})
	coord.applyComponentState(runtime.ComponentComponentState{
		Component: comp2,
		State: runtime.ComponentState{
			State: client.UnitStateStopped,
		},
	})

	// Both process runtime components must still be present and healthy.
	require.Len(t, coord.state.Components, 2,
		"late STOPPED from otel runtime must not remove process runtime components")

	componentsByID := make(map[string]runtime.ComponentComponentState, len(coord.state.Components))
	for _, cs := range coord.state.Components {
		componentsByID[cs.Component.ID] = cs
	}

	for _, id := range []string{metricsID, filestreamID} {
		cs, ok := componentsByID[id]
		require.True(t, ok, "component %s should still be present", id)
		assert.Equal(t, client.UnitStateHealthy, cs.State.State,
			"component %s should still be healthy", id)
		assert.Equal(t, pkgcomponent.ProcessRuntimeManager, cs.Component.RuntimeManager,
			"component %s should still be under process runtime", id)
	}
}

func TestApplyComponentState_StoppedFromSameRuntimeRemovesComponent(t *testing.T) {
	coord := &Coordinator{
		logger: logp.NewLogger("testing"),
		state: State{
			CoordinatorState:   agentclient.Healthy,
			CoordinatorMessage: "Running",
		},
		stateBroadcaster: broadcaster.New(State{}, 0, 0),
	}

	coord.applyComponentState(runtime.ComponentComponentState{
		Component: pkgcomponent.Component{
			ID:             "filestream-default",
			RuntimeManager: pkgcomponent.ProcessRuntimeManager,
		},
		State: runtime.ComponentState{
			State:   client.UnitStateHealthy,
			Message: "Healthy",
		},
	})
	require.Len(t, coord.state.Components, 1)

	coord.applyComponentState(runtime.ComponentComponentState{
		Component: pkgcomponent.Component{
			ID:             "filestream-default",
			RuntimeManager: pkgcomponent.ProcessRuntimeManager,
		},
		State: runtime.ComponentState{
			State: client.UnitStateStopped,
		},
	})

	assert.Empty(t, coord.state.Components,
		"STOPPED from the same runtime should remove the component")
}

func TestApplyComponentState_StartingFromNewRuntimeReplacesExisting(t *testing.T) {
	coord := &Coordinator{
		state: State{
			CoordinatorState:   agentclient.Healthy,
			CoordinatorMessage: "Running",
		},
		stateBroadcaster: broadcaster.New(State{}, 0, 0),
	}

	coord.applyComponentState(runtime.ComponentComponentState{
		Component: pkgcomponent.Component{
			ID:               "filestream-default",
			RuntimeManager:   pkgcomponent.OtelRuntimeManager,
			LastConfiguredAt: time.Now(),
		},
		State: runtime.ComponentState{
			State:   client.UnitStateHealthy,
			Message: "Healthy",
		},
	})
	require.Len(t, coord.state.Components, 1)
	assert.Equal(t, pkgcomponent.OtelRuntimeManager, coord.state.Components[0].Component.RuntimeManager)

	coord.applyComponentState(runtime.ComponentComponentState{
		Component: pkgcomponent.Component{
			ID:               "filestream-default",
			RuntimeManager:   pkgcomponent.ProcessRuntimeManager,
			LastConfiguredAt: time.Now(),
		},
		State: runtime.ComponentState{
			State:   client.UnitStateStarting,
			Message: "Starting",
		},
	})

	require.Len(t, coord.state.Components, 1,
		"STARTING from new runtime should replace, not duplicate")
	assert.Equal(t, pkgcomponent.ProcessRuntimeManager, coord.state.Components[0].Component.RuntimeManager,
		"component should now be under process runtime")
	assert.Equal(t, client.UnitStateStarting, coord.state.Components[0].State.State)
}

func TestRecoverableActionsError(t *testing.T) {
	pingErr := errors.New("fleet server ping returned a bad status code: 429")

	tt := []struct {
		id       string
		err      error
		expected agentclient.State
	}{
		{"no error", nil, agentclient.Healthy},
		{"plain error", pingErr, agentclient.Failed},
		{"recoverable error", errors.NewRecoverable(pingErr), agentclient.Degraded},
		{"wrapped recoverable error", fmt.Errorf("validating fleet client config: %w", errors.NewRecoverable(pingErr)), agentclient.Degraded},
	}

	for _, tc := range tt {
		t.Run(tc.id, func(t *testing.T) {
			coord := &Coordinator{
				state: State{
					CoordinatorState:   agentclient.Healthy,
					CoordinatorMessage: "Running",
				},
				actionsErr: tc.err,
			}

			state := coord.generateReportableState()
			assert.Equal(t, tc.expected, state.State)
			if tc.err != nil {
				var expectedMsg string
				if tc.expected == agentclient.Degraded {
					expectedMsg = "Actions degraded: " + tc.err.Error()
				} else {
					expectedMsg = "Actions failed: " + tc.err.Error()
				}
				assert.Equal(t, expectedMsg, state.Message)
			}
		})
	}
}

const (
	capNotEnforcedMessage = "CPU limit is not enforced as requested"
	removalFailedMessage  = "The CPU quota of the Agent could not be removed"
)

func TestCPULimitHealth(t *testing.T) {
	capOn := cpuLimitPercent(t, 50)
	degraded := &cpulimit.Snapshot{State: cpulimit.StateDegraded, Configured: capOn, Err: errors.New("quota mismatch")}
	// removalFailed is a failed removal of the agent quota after the cap was turned off.
	removalFailed := &cpulimit.Snapshot{State: cpulimit.StateDegraded, Err: errors.New("remove failed")}
	failedComponents := []runtime.ComponentComponentState{{
		Component: pkgcomponent.Component{ID: "comp-1"},
		State:     runtime.ComponentState{State: client.UnitStateFailed},
	}}
	degradedComponents := []runtime.ComponentComponentState{{
		Component: pkgcomponent.Component{ID: "comp-1"},
		State:     runtime.ComponentState{State: client.UnitStateDegraded},
	}}

	tt := []struct {
		id         string
		cpuLimit   *cpulimit.Snapshot
		coordState agentclient.State
		coordMsg   string
		override   *coordinatorOverrideState
		configErr  error
		actionsErr error
		components []runtime.ComponentComponentState
		// held and timedOut tell whether components wait for the CPU cap and whether the wait timed out.
		held     bool
		timedOut bool
		expected agentclient.State
		// expectedMsg is the exact message. When empty, the message must contain each of expectedMsgParts.
		expectedMsg      string
		expectedMsgParts []string
	}{
		{id: "no controller", expected: agentclient.Healthy, expectedMsg: "Running"},
		{id: "disabled", cpuLimit: &cpulimit.Snapshot{State: cpulimit.StateDisabled}, expected: agentclient.Healthy, expectedMsg: "Running"},
		{id: "removal pending", cpuLimit: &cpulimit.Snapshot{State: cpulimit.StatePending}, expected: agentclient.Healthy, expectedMsg: "Running"},
		{id: "removal failed", cpuLimit: removalFailed, expected: agentclient.Degraded, expectedMsg: removalFailedMessage},
		{id: "removal failed with degraded component", cpuLimit: removalFailed, components: degradedComponents, expected: agentclient.Degraded, expectedMsg: "1 or more components/units in a degraded state"},
		{id: "removal failed with starting coordinator", cpuLimit: removalFailed, coordState: agentclient.Starting, coordMsg: "Starting", expected: agentclient.Starting, expectedMsg: "Starting"},
		{id: "pending", cpuLimit: &cpulimit.Snapshot{State: cpulimit.StatePending, Configured: capOn}, expected: agentclient.Healthy, expectedMsg: "Running"},
		{id: "applied", cpuLimit: &cpulimit.Snapshot{State: cpulimit.StateApplied}, expected: agentclient.Healthy, expectedMsg: "Running"},
		{
			id: "applied with lower effective quota",
			cpuLimit: &cpulimit.Snapshot{
				State:          cpulimit.StateApplied,
				Configured:     capOn,
				TargetCPUs:     2,
				ActiveQuota:    cpulimit.Quota{Kind: cpulimit.QuotaSet, CPUs: 2},
				EffectiveQuota: cpulimit.Quota{Kind: cpulimit.QuotaSet, CPUs: 1},
			},
			expected:    agentclient.Healthy,
			expectedMsg: "Running",
		},
		{
			id:          "unsupported",
			cpuLimit:    &cpulimit.Snapshot{State: cpulimit.StateUnsupported, Reason: "not supported"},
			expected:    agentclient.Healthy,
			expectedMsg: "Running",
		},
		{
			id:          "error without degraded state",
			cpuLimit:    &cpulimit.Snapshot{State: cpulimit.StatePending, Err: errors.New("quota mismatch")},
			expected:    agentclient.Healthy,
			expectedMsg: "Running",
		},
		{
			id:          "degraded",
			cpuLimit:    degraded,
			expected:    agentclient.Degraded,
			expectedMsg: capNotEnforcedMessage,
		},
		{
			id:          "degraded without error",
			cpuLimit:    &cpulimit.Snapshot{State: cpulimit.StateDegraded, Configured: capOn},
			expected:    agentclient.Degraded,
			expectedMsg: capNotEnforcedMessage,
		},
		{
			id:          "degraded with invalid policy",
			cpuLimit:    degraded,
			configErr:   errors.New("bad policy"),
			expected:    agentclient.Failed,
			expectedMsg: "Invalid policy: bad policy",
		},
		{
			id:          "degraded with failed component",
			cpuLimit:    degraded,
			components:  failedComponents,
			expected:    agentclient.Degraded,
			expectedMsg: "1 or more components/units in a failed state",
		},
		{
			id:          "degraded with degraded component",
			cpuLimit:    degraded,
			components:  degradedComponents,
			expected:    agentclient.Degraded,
			expectedMsg: "1 or more components/units in a degraded state",
		},
		{
			id:          "degraded with override state",
			cpuLimit:    degraded,
			override:    &coordinatorOverrideState{state: agentclient.Upgrading, message: "Upgrading"},
			expected:    agentclient.Upgrading,
			expectedMsg: "Upgrading",
		},
		{
			id:          "degraded with failed coordinator",
			cpuLimit:    degraded,
			coordState:  agentclient.Failed,
			coordMsg:    "Fatal coordinator error",
			expected:    agentclient.Failed,
			expectedMsg: "Fatal coordinator error",
		},
		{
			id:          "degraded with stopped coordinator",
			cpuLimit:    degraded,
			coordState:  agentclient.Stopped,
			coordMsg:    "Requested to be stopped",
			expected:    agentclient.Stopped,
			expectedMsg: "Requested to be stopped",
		},
		{
			id:          "degraded with starting coordinator",
			cpuLimit:    degraded,
			coordState:  agentclient.Starting,
			coordMsg:    "Starting",
			expected:    agentclient.Starting,
			expectedMsg: "Starting",
		},
		{id: "held", held: true, expected: agentclient.Starting, expectedMsg: gateWaitingMessage},
		{id: "held with invalid policy", held: true, configErr: errors.New("bad policy"), expected: agentclient.Failed, expectedMsg: "Invalid policy: bad policy"},
		{id: "held with failed component", held: true, components: failedComponents, expected: agentclient.Degraded, expectedMsg: "1 or more components/units in a failed state"},
		{id: "held with degraded CPU limit", held: true, cpuLimit: degraded, expected: agentclient.Degraded, expectedMsg: capNotEnforcedMessage},
		{id: "held with override state", held: true, override: &coordinatorOverrideState{state: agentclient.Upgrading, message: "Upgrading"}, expected: agentclient.Upgrading, expectedMsg: "Upgrading"},
		{id: "held with stopped coordinator", held: true, coordState: agentclient.Stopped, coordMsg: "Requested to be stopped", expected: agentclient.Stopped, expectedMsg: "Requested to be stopped"},
		{id: "held with failed coordinator", held: true, coordState: agentclient.Failed, coordMsg: "Fatal coordinator error", expected: agentclient.Failed, expectedMsg: "Fatal coordinator error"},
		{id: "held after the timeout", held: true, timedOut: true, expected: agentclient.Failed, expectedMsgParts: []string{"CPU limit"}},
		{id: "held after the timeout with failed component", held: true, timedOut: true, components: failedComponents, expected: agentclient.Failed, expectedMsgParts: []string{"CPU limit"}},
		{id: "held after the timeout with invalid policy", held: true, timedOut: true, configErr: errors.New("bad policy"), expected: agentclient.Failed, expectedMsg: "Invalid policy: bad policy"},
		{id: "held with recoverable actions error", held: true, actionsErr: errors.NewRecoverable(errors.New("ping failed")), expected: agentclient.Degraded, expectedMsg: "Actions degraded: ping failed"},
		{id: "held after the timeout with recoverable actions error", held: true, timedOut: true, actionsErr: errors.NewRecoverable(errors.New("ping failed")), expected: agentclient.Failed, expectedMsgParts: []string{"CPU limit"}},
		{id: "held after the timeout with actions error", held: true, timedOut: true, actionsErr: errors.New("ack failed"), expected: agentclient.Failed, expectedMsg: "Actions failed: ack failed"},
		{id: "held after the timeout with override state", held: true, timedOut: true, override: &coordinatorOverrideState{state: agentclient.Upgrading, message: "Upgrading"}, expected: agentclient.Upgrading, expectedMsg: "Upgrading"},
		{id: "held after the timeout with stopped coordinator", held: true, timedOut: true, coordState: agentclient.Stopped, coordMsg: "Requested to be stopped", expected: agentclient.Stopped, expectedMsg: "Requested to be stopped"},
	}

	for _, tc := range tt {
		t.Run(tc.id, func(t *testing.T) {
			coordState, coordMsg := agentclient.Healthy, "Running"
			if tc.coordMsg != "" {
				coordState, coordMsg = tc.coordState, tc.coordMsg
			}
			coord := &Coordinator{
				state: State{
					CoordinatorState:   coordState,
					CoordinatorMessage: coordMsg,
					Components:         tc.components,
					CPULimit:           tc.cpuLimit,
				},
				overrideState:         tc.override,
				configErr:             tc.configErr,
				actionsErr:            tc.actionsErr,
				cpuLimitHeld:          tc.held,
				cpuLimitStartTimedOut: tc.timedOut,
			}

			state := coord.generateReportableState()
			assert.Equal(t, tc.expected, state.State)
			if tc.expectedMsg != "" {
				assert.Equal(t, tc.expectedMsg, state.Message)
			}
			for _, part := range tc.expectedMsgParts {
				assert.Contains(t, state.Message, part)
			}
			if tc.cpuLimit != nil && tc.cpuLimit.Err != nil {
				assert.NotContains(t, state.Message, tc.cpuLimit.Err.Error(), "the CPU limit error must not reach the health message")
			}
		})
	}

	t.Run("recovery", func(t *testing.T) {
		coord := &Coordinator{
			state: State{
				CoordinatorState:   agentclient.Healthy,
				CoordinatorMessage: "Running",
				CPULimit:           degraded,
			},
		}
		require.Equal(t, agentclient.Degraded, coord.generateReportableState().State)

		coord.state.CPULimit = &cpulimit.Snapshot{State: cpulimit.StateApplied}
		state := coord.generateReportableState()
		assert.Equal(t, agentclient.Healthy, state.State)
		assert.Equal(t, "Running", state.Message)
	})
}

func TestSetCPULimitStateRefresh(t *testing.T) {
	degraded := cpulimit.Snapshot{
		State:          cpulimit.StateDegraded,
		Configured:     cpuLimitPercent(t, 50),
		TargetCPUs:     2,
		ActiveQuota:    cpulimit.Quota{Kind: cpulimit.QuotaSet, CPUs: 2},
		EffectiveQuota: cpulimit.Quota{Kind: cpulimit.QuotaSet, CPUs: 2},
		Err:            errors.New("quota mismatch"),
		Reason:         "reason",
	}
	// changed returns a copy of degraded with a new error of the same text and with f applied.
	changed := func(f func(s *cpulimit.Snapshot)) cpulimit.Snapshot {
		s := degraded
		s.Err = errors.New("quota mismatch")
		f(&s)
		return s
	}

	tt := []struct {
		id      string
		next    cpulimit.Snapshot
		refresh bool
	}{
		{id: "nothing changed", next: changed(func(*cpulimit.Snapshot) {}), refresh: false},
		{id: "state changed", next: changed(func(s *cpulimit.Snapshot) { s.State = cpulimit.StateApplied }), refresh: true},
		{id: "configured limit changed", next: changed(func(s *cpulimit.Snapshot) { s.Configured = cpuLimitPercent(t, 60) }), refresh: true},
		{id: "target CPUs changed", next: changed(func(s *cpulimit.Snapshot) { s.TargetCPUs = 3 }), refresh: true},
		{id: "active quota changed", next: changed(func(s *cpulimit.Snapshot) { s.ActiveQuota.CPUs = 3 }), refresh: true},
		{id: "effective quota changed", next: changed(func(s *cpulimit.Snapshot) { s.EffectiveQuota.CPUs = 1 }), refresh: true},
		{id: "effective quota unknown", next: changed(func(s *cpulimit.Snapshot) { s.EffectiveQuota = cpulimit.Quota{} }), refresh: true},
		{id: "reason changed", next: changed(func(s *cpulimit.Snapshot) { s.Reason = "other reason" }), refresh: true},
		{id: "error text changed", next: changed(func(s *cpulimit.Snapshot) { s.Err = errors.New("inspect failed") }), refresh: true},
		{id: "error cleared", next: changed(func(s *cpulimit.Snapshot) { s.Err = nil }), refresh: true},
	}

	for _, tc := range tt {
		t.Run(tc.id, func(t *testing.T) {
			old := degraded
			coord := &Coordinator{state: State{CPULimit: &old}}

			coord.setCPULimitState(tc.next)
			assert.Equal(t, tc.refresh, coord.stateNeedsRefresh)
			require.NotNil(t, coord.state.CPULimit)
			assert.Equal(t, tc.next, *coord.state.CPULimit)
		})
	}

	t.Run("first state", func(t *testing.T) {
		coord := &Coordinator{}
		coord.setCPULimitState(degraded)
		assert.True(t, coord.stateNeedsRefresh)
		require.NotNil(t, coord.state.CPULimit)
		assert.Equal(t, degraded, *coord.state.CPULimit)
	})

	t.Run("cap turned off", func(t *testing.T) {
		old := degraded
		coord := &Coordinator{state: State{CPULimit: &old}}
		coord.setCPULimitState(cpulimit.Snapshot{State: cpulimit.StateDisabled})
		assert.True(t, coord.stateNeedsRefresh)
		require.NotNil(t, coord.state.CPULimit)
		assert.Equal(t, cpulimit.Snapshot{State: cpulimit.StateDisabled}, *coord.state.CPULimit)
	})

	t.Run("still disabled", func(t *testing.T) {
		coord := &Coordinator{state: State{CPULimit: &cpulimit.Snapshot{State: cpulimit.StateDisabled}}}
		coord.setCPULimitState(cpulimit.Snapshot{State: cpulimit.StateDisabled})
		assert.False(t, coord.stateNeedsRefresh)
		require.NotNil(t, coord.state.CPULimit)
		assert.Equal(t, cpulimit.StateDisabled, coord.state.CPULimit.State)
	})
}

func TestReportedCPULimitStateIsACopy(t *testing.T) {
	coord := &Coordinator{}
	coord.setCPULimitState(cpulimit.Snapshot{State: cpulimit.StateApplied})

	reported := coord.generateReportableState()
	require.NotNil(t, reported.CPULimit)
	reported.CPULimit.State = cpulimit.StateDegraded
	assert.Equal(t, cpulimit.StateApplied, coord.state.CPULimit.State, "a change to the reported state must not reach the coordinator")
}
