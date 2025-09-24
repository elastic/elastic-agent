// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package monitoringhelpers

import (
	"testing"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/elastic/elastic-agent/pkg/component/runtime"
)

func TestComponentsHasState(t *testing.T) {
	tests := []struct {
		name       string
		components []runtime.ComponentComponentState
		state      client.UnitState
		expected   bool
	}{
		{
			name: "component with no units matches state",
			components: []runtime.ComponentComponentState{
				{
					State: runtime.ComponentState{
						State: client.UnitStateHealthy,
						Units: map[runtime.ComponentUnitKey]runtime.ComponentUnitState{},
					},
				},
			},
			state:    client.UnitStateHealthy,
			expected: true,
		},
		{
			name: "component with units in different state matches state",
			components: []runtime.ComponentComponentState{
				{
					State: runtime.ComponentState{
						State: client.UnitStateHealthy,
						Units: map[runtime.ComponentUnitKey]runtime.ComponentUnitState{
							{
								UnitType: client.UnitTypeInput,
								UnitID:   "some-input-unit",
							}: {
								State: client.UnitStateFailed,
							},
						},
					},
				},
			},
			state:    client.UnitStateHealthy,
			expected: true,
		},
		{
			name: "unit matches state",
			components: []runtime.ComponentComponentState{
				{
					State: runtime.ComponentState{
						State: client.UnitStateDegraded,
						Units: map[runtime.ComponentUnitKey]runtime.ComponentUnitState{
							{
								UnitType: client.UnitTypeInput,
								UnitID:   "some-input-unit",
							}: {
								State: client.UnitStateHealthy,
							},
						},
					},
				},
			},
			state:    client.UnitStateHealthy,
			expected: true,
		},
		{
			name: "no match in single component",
			components: []runtime.ComponentComponentState{
				{
					State: runtime.ComponentState{
						State: client.UnitStateDegraded,
						Units: map[runtime.ComponentUnitKey]runtime.ComponentUnitState{
							{
								UnitType: client.UnitTypeInput,
								UnitID:   "some-input-unit",
							}: {
								State: client.UnitStateStopped,
							},
						},
					},
				},
			},
			state:    client.UnitStateHealthy,
			expected: false,
		},
		{
			name: "match in second component",
			components: []runtime.ComponentComponentState{
				{
					State: runtime.ComponentState{
						State: client.UnitStateDegraded,
						Units: map[runtime.ComponentUnitKey]runtime.ComponentUnitState{},
					},
				},
				{
					State: runtime.ComponentState{
						State: client.UnitStateHealthy,
						Units: map[runtime.ComponentUnitKey]runtime.ComponentUnitState{},
					},
				},
			},
			state:    client.UnitStateHealthy,
			expected: true,
		},
		{
			name:       "empty components slice",
			components: []runtime.ComponentComponentState{},
			state:      client.UnitStateHealthy,
			expected:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := HaveState(tt.components, tt.state)
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}
