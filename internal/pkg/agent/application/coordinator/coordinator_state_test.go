// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package coordinator

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"
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
