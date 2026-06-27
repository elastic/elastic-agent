// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package coordinator

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/elastic/elastic-agent-client/v7/pkg/proto"
	"github.com/elastic/elastic-agent-libs/logp"

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

func TestHasStateSuppressHealthDegradation(t *testing.T) {
	const unitID = "metrics-unit"

	build := func(unitState client.UnitState, statusReporting map[string]any) []runtime.ComponentComponentState {
		var src *structpb.Struct
		if statusReporting != nil {
			s, err := structpb.NewStruct(map[string]any{"status_reporting": statusReporting})
			require.NoError(t, err)
			src = s
		}
		key := runtime.ComponentUnitKey{UnitType: client.UnitTypeInput, UnitID: unitID}
		return []runtime.ComponentComponentState{{
			Component: pkgcomponent.Component{
				ID: "test-comp",
				Units: []pkgcomponent.Unit{{
					ID:     unitID,
					Type:   client.UnitTypeInput,
					Config: &proto.UnitExpectedConfig{Source: src},
				}},
			},
			State: runtime.ComponentState{
				State: client.UnitStateHealthy,
				Units: map[runtime.ComponentUnitKey]runtime.ComponentUnitState{
					key: {State: unitState},
				},
			},
		}}
	}

	tests := []struct {
		name       string
		unitState  client.UnitState
		reporting  map[string]any
		queryState client.UnitState
		want       bool
	}{
		{"failed, no config -> counts", client.UnitStateFailed, nil, client.UnitStateFailed, true},
		{"failed, report_failed=false -> suppressed", client.UnitStateFailed, map[string]any{"report_failed": false}, client.UnitStateFailed, false},
		{"failed, report_failed=true -> counts", client.UnitStateFailed, map[string]any{"report_failed": true}, client.UnitStateFailed, true},
		{"degraded, no config -> counts", client.UnitStateDegraded, nil, client.UnitStateDegraded, true},
		{"degraded, report_degraded=false -> suppressed", client.UnitStateDegraded, map[string]any{"report_degraded": false}, client.UnitStateDegraded, false},
		{"failed, only report_degraded=false -> failed still counts", client.UnitStateFailed, map[string]any{"report_degraded": false}, client.UnitStateFailed, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, hasState(build(tc.unitState, tc.reporting), tc.queryState))
		})
	}
}

// TestGenerateReportableStateSuppressHealthDegradation drives the real
// generateReportableState() (the function the Fleet-reported agent status comes
// from) with components/units in various states and status_reporting configs,
// to validate the end-to-end aggregate-health behavior of the change.
func TestGenerateReportableStateSuppressHealthDegradation(t *testing.T) {
	unit := func(id string, st client.UnitState, sr map[string]any) runtime.ComponentComponentState {
		var src *structpb.Struct
		if sr != nil {
			s, err := structpb.NewStruct(map[string]any{"status_reporting": sr})
			require.NoError(t, err)
			src = s
		}
		key := runtime.ComponentUnitKey{UnitType: client.UnitTypeInput, UnitID: id}
		return runtime.ComponentComponentState{
			Component: pkgcomponent.Component{
				ID:    id,
				Units: []pkgcomponent.Unit{{ID: id, Type: client.UnitTypeInput, Config: &proto.UnitExpectedConfig{Source: src}}},
			},
			State: runtime.ComponentState{
				State: client.UnitStateHealthy,
				Units: map[runtime.ComponentUnitKey]runtime.ComponentUnitState{key: {State: st}},
			},
		}
	}

	suppressFailed := map[string]any{"report_failed": false}
	suppressDegraded := map[string]any{"report_degraded": false}
	suppressBoth := map[string]any{"report_failed": false, "report_degraded": false}

	tests := []struct {
		name  string
		comps []runtime.ComponentComponentState
		want  agentclient.State
	}{
		{"no components -> Healthy", nil, agentclient.Healthy},
		{"healthy unit -> Healthy", []runtime.ComponentComponentState{unit("a", client.UnitStateHealthy, nil)}, agentclient.Healthy},
		{"failed, unsuppressed -> Degraded", []runtime.ComponentComponentState{unit("a", client.UnitStateFailed, nil)}, agentclient.Degraded},
		{"failed, suppressed -> Healthy", []runtime.ComponentComponentState{unit("a", client.UnitStateFailed, suppressFailed)}, agentclient.Healthy},
		{"degraded, unsuppressed -> Degraded", []runtime.ComponentComponentState{unit("a", client.UnitStateDegraded, nil)}, agentclient.Degraded},
		{"degraded, suppressed -> Healthy", []runtime.ComponentComponentState{unit("a", client.UnitStateDegraded, suppressDegraded)}, agentclient.Healthy},
		{"mixed: suppressed-failed + unsuppressed-degraded -> Degraded", []runtime.ComponentComponentState{unit("a", client.UnitStateFailed, suppressBoth), unit("b", client.UnitStateDegraded, nil)}, agentclient.Degraded},
		{"mixed: all suppressed -> Healthy", []runtime.ComponentComponentState{unit("a", client.UnitStateFailed, suppressBoth), unit("b", client.UnitStateDegraded, suppressDegraded)}, agentclient.Healthy},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			coord := &Coordinator{
				state: State{
					CoordinatorState:   agentclient.Healthy,
					CoordinatorMessage: "Running",
					Components:         tc.comps,
				},
			}
			s := coord.generateReportableState()
			assert.Equal(t, tc.want, s.State, "message: %s", s.Message)
		})
	}
}
