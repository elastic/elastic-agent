// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package testing

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/pkg/control/v2/client"
)

type NextCall struct {
	AgentState *client.AgentState
	Configure  string
	Continue   bool
	Err        error
}

func TestStateMachine(t *testing.T) {
	scenarios := []struct {
		Name        string
		States      []State
		AgentStates []NextCall
		Err         error
	}{
		{
			Name: "no states",
			Err:  errors.New("must defined at least 1 state"),
		},
		{
			Name: "no config",
			States: []State{
				{
					AgentState: NewClientState(client.Healthy),
				},
			},
			Err: errors.New("at least one state must define a configuration"),
		},
		{
			Name: "no agent Reached defined",
			States: []State{
				{},
			},
			Err: errors.New("state 0 invalid: must define Reached if no AgentState, FleetState, Components, or StrictComponents is not defined"),
		},
		{
			Name: "no component Reached defined",
			States: []State{
				{
					Components: map[string]ComponentState{
						"simple": {},
					},
				},
			},
			Err: errors.New("state 0 invalid: component simple invalid: must define Reached if no State, Units, or StrictUnits is not defined"),
		},
		{
			Name: "no strict component Reached defined",
			States: []State{
				{
					StrictComponents: map[string]ComponentState{
						"simple": {},
					},
				},
			},
			Err: errors.New("state 0 invalid: strict component simple invalid: must define Reached if no State, Units, or StrictUnits is not defined"),
		},
		{
			Name: "no unit Reached defined",
			States: []State{
				{
					Components: map[string]ComponentState{
						"simple": {
							Units: map[ComponentUnitKey]ComponentUnitState{
								ComponentUnitKey{UnitType: client.UnitTypeInput, UnitID: "unit-0"}: {},
							},
						},
					},
				},
			},
			Err: errors.New("state 0 invalid: component simple invalid: unit (INPUT) unit-0 invalid: must define Reached if no State defined"),
		},
		{
			Name: "no strict unit Reached defined",
			States: []State{
				{
					Components: map[string]ComponentState{
						"simple": {
							StrictUnits: map[ComponentUnitKey]ComponentUnitState{
								ComponentUnitKey{UnitType: client.UnitTypeInput, UnitID: "unit-0"}: {},
							},
						},
					},
				},
			},
			Err: errors.New("state 0 invalid: component simple invalid: strict unit (INPUT) unit-0 invalid: must define Reached if no State defined"),
		},
		{
			Name: "agent state only",
			States: []State{
				{
					Configure:  "my config",
					AgentState: NewClientState(client.Healthy),
				},
			},
			AgentStates: []NextCall{
				{
					Configure: "my config",
					Continue:  true,
				},
				{
					AgentState: &client.AgentState{State: client.Starting},
					Continue:   true,
				},
				{
					AgentState: &client.AgentState{State: client.Configuring},
					Continue:   true,
				},
				{
					AgentState: &client.AgentState{State: client.Healthy},
					Continue:   false,
				},
			},
		},
		{
			Name: "fleet state only",
			States: []State{
				{
					Configure:  "my config",
					FleetState: NewClientState(client.Healthy),
				},
			},
			AgentStates: []NextCall{
				{
					AgentState: &client.AgentState{FleetState: client.Starting},
					Configure:  "my config",
					Continue:   true,
				},
				{
					AgentState: &client.AgentState{FleetState: client.Configuring},
					Continue:   true,
				},
				{
					AgentState: &client.AgentState{FleetState: client.Healthy},
					Continue:   false,
				},
			},
		},
		{
			Name: "agent/fleet state",
			States: []State{
				{
					Configure:  "my config",
					AgentState: NewClientState(client.Healthy),
					FleetState: NewClientState(client.Healthy),
				},
			},
			AgentStates: []NextCall{
				{
					AgentState: &client.AgentState{State: client.Starting, FleetState: client.Starting},
					Configure:  "my config",
					Continue:   true,
				},
				{
					AgentState: &client.AgentState{State: client.Starting, FleetState: client.Healthy},
					Continue:   true,
				},
				{
					AgentState: &client.AgentState{State: client.Healthy, FleetState: client.Failed},
					Continue:   true,
				},
				{
					AgentState: &client.AgentState{State: client.Healthy, FleetState: client.Healthy},
					Continue:   false,
				},
			},
		},
		{
			Name: "agent reached validator",
			States: []State{
				{
					Configure: "my config",
					Reached: func(state *client.AgentState) bool {
						return state.State == client.Healthy && state.FleetState == client.Healthy && state.FleetMessage == "Connected"
					},
				},
			},
			AgentStates: []NextCall{
				{
					AgentState: &client.AgentState{State: client.Starting, FleetState: client.Starting},
					Configure:  "my config",
					Continue:   true,
				},
				{
					AgentState: &client.AgentState{State: client.Starting, FleetState: client.Healthy},
					Continue:   true,
				},
				{
					AgentState: &client.AgentState{State: client.Healthy, FleetState: client.Failed},
					Continue:   true,
				},
				{
					AgentState: &client.AgentState{State: client.Healthy, FleetState: client.Healthy},
					Continue:   true,
				},
				{
					AgentState: &client.AgentState{State: client.Healthy, FleetState: client.Healthy, FleetMessage: "Connected"},
					Continue:   false,
				},
			},
		},
		{
			Name: "change configuration",
			States: []State{
				{
					Configure:  "my config",
					AgentState: NewClientState(client.Healthy),
				},
				{
					Configure:  "reconfigure",
					AgentState: NewClientState(client.Configuring),
				},
				{
					AgentState: NewClientState(client.Healthy),
				},
			},
			AgentStates: []NextCall{
				{
					AgentState: &client.AgentState{State: client.Starting},
					Configure:  "my config",
					Continue:   true,
				},
				{
					AgentState: &client.AgentState{State: client.Healthy},
					Configure:  "reconfigure",
					Continue:   true,
				},
				{
					AgentState: &client.AgentState{State: client.Configuring},
					Continue:   true,
				},
				{
					AgentState: &client.AgentState{State: client.Healthy},
					Continue:   false,
				},
			},
		},
		{
			Name: "component state",
			States: []State{
				{
					Configure: "my config",
					Components: map[string]ComponentState{
						"test": {
							State: NewClientState(client.Healthy),
						},
					},
				},
			},
			AgentStates: []NextCall{
				{
					AgentState: &client.AgentState{},
					Configure:  "my config",
					Continue:   true,
				},
				{
					AgentState: &client.AgentState{
						Components: []client.ComponentState{
							{
								ID:    "test",
								State: client.Starting,
							},
						},
					},
					Continue: true,
				},
				{
					AgentState: &client.AgentState{
						Components: []client.ComponentState{
							{
								ID:    "test",
								State: client.Configuring,
							},
						},
					},
					Continue: true,
				},
				{
					AgentState: &client.AgentState{
						Components: []client.ComponentState{
							{
								ID:    "test",
								State: client.Healthy,
							},
							{
								ID:    "other",
								State: client.Starting,
							},
						},
					},
					Continue: false,
				},
			},
		},
		{
			Name: "strict component state",
			States: []State{
				{
					Configure: "my config",
					StrictComponents: map[string]ComponentState{
						"test": {
							State: NewClientState(client.Healthy),
						},
					},
				},
			},
			AgentStates: []NextCall{
				{
					AgentState: &client.AgentState{},
					Configure:  "my config",
					Continue:   true,
				},
				{
					AgentState: &client.AgentState{
						Components: []client.ComponentState{
							{
								ID:    "test",
								State: client.Starting,
							},
						},
					},
					Continue: true,
				},
				{
					AgentState: &client.AgentState{
						Components: []client.ComponentState{
							{
								ID:    "test",
								State: client.Configuring,
							},
						},
					},
					Continue: true,
				},
				{
					AgentState: &client.AgentState{
						Components: []client.ComponentState{
							{
								ID:    "test",
								State: client.Healthy,
							},
							{
								ID:    "other",
								State: client.Starting,
							},
						},
					},
					Continue: true,
				},
				{
					AgentState: &client.AgentState{
						Components: []client.ComponentState{
							{
								ID:    "test",
								State: client.Healthy,
							},
						},
					},
					Continue: false,
				},
			},
		},
		{
			Name: "component reached callback",
			States: []State{
				{
					Configure: "my config",
					Components: map[string]ComponentState{
						"test": {
							Reached: func(state *client.ComponentState) bool {
								return state.State == client.Healthy && state.Message == "Specific Message"
							},
						},
					},
				},
			},
			AgentStates: []NextCall{
				{
					AgentState: &client.AgentState{},
					Configure:  "my config",
					Continue:   true,
				},
				{
					AgentState: &client.AgentState{
						Components: []client.ComponentState{
							{
								ID:    "test",
								State: client.Starting,
							},
						},
					},
					Continue: true,
				},
				{
					AgentState: &client.AgentState{
						Components: []client.ComponentState{
							{
								ID:    "test",
								State: client.Configuring,
							},
						},
					},
					Continue: true,
				},
				{
					AgentState: &client.AgentState{
						Components: []client.ComponentState{
							{
								ID:      "test",
								State:   client.Healthy,
								Message: "Not a Specific Message",
							},
						},
					},
					Continue: true,
				},
				{
					AgentState: &client.AgentState{
						Components: []client.ComponentState{
							{
								ID:      "test",
								State:   client.Healthy,
								Message: "Specific Message",
							},
						},
					},
					Continue: false,
				},
			},
		},
		{
			Name: "unit state",
			States: []State{
				{
					Configure: "my config",
					Components: map[string]ComponentState{
						"test": {
							Units: map[ComponentUnitKey]ComponentUnitState{
								ComponentUnitKey{UnitType: client.UnitTypeInput, UnitID: "input"}: {
									State: NewClientState(client.Healthy),
								},
							},
						},
					},
				},
			},
			AgentStates: []NextCall{
				{
					AgentState: &client.AgentState{},
					Configure:  "my config",
					Continue:   true,
				},
				{
					AgentState: &client.AgentState{
						Components: []client.ComponentState{
							{
								ID: "test",
							},
						},
					},
					Continue: true,
				},
				{
					AgentState: &client.AgentState{
						Components: []client.ComponentState{
							{
								ID: "test",
								Units: []client.ComponentUnitState{
									{
										UnitType: client.UnitTypeInput,
										UnitID:   "input",
										State:    client.Starting,
									},
								},
							},
						},
					},
					Continue: true,
				},
				{
					AgentState: &client.AgentState{
						Components: []client.ComponentState{
							{
								ID: "test",
								Units: []client.ComponentUnitState{
									{
										UnitType: client.UnitTypeInput,
										UnitID:   "input",
										State:    client.Configuring,
									},
								},
							},
						},
					},
					Continue: true,
				},
				{
					AgentState: &client.AgentState{
						Components: []client.ComponentState{
							{
								ID: "test",
								Units: []client.ComponentUnitState{
									{
										UnitType: client.UnitTypeInput,
										UnitID:   "input",
										State:    client.Healthy,
									},
									{
										UnitType: client.UnitTypeOutput,
										UnitID:   "other",
										State:    client.Healthy,
									},
								},
							},
						},
					},
					Continue: false,
				},
			},
		},
		{
			Name: "strict unit state",
			States: []State{
				{
					Configure: "my config",
					Components: map[string]ComponentState{
						"test": {
							StrictUnits: map[ComponentUnitKey]ComponentUnitState{
								ComponentUnitKey{UnitType: client.UnitTypeInput, UnitID: "input"}: {
									State: NewClientState(client.Healthy),
								},
							},
						},
					},
				},
			},
			AgentStates: []NextCall{
				{
					AgentState: &client.AgentState{},
					Configure:  "my config",
					Continue:   true,
				},
				{
					AgentState: &client.AgentState{},
					Continue:   true,
				},
				{
					AgentState: &client.AgentState{
						Components: []client.ComponentState{
							{
								ID: "test",
							},
						},
					},
					Continue: true,
				},
				{
					AgentState: &client.AgentState{
						Components: []client.ComponentState{
							{
								ID: "test",
								Units: []client.ComponentUnitState{
									{
										UnitType: client.UnitTypeInput,
										UnitID:   "input",
										State:    client.Starting,
									},
								},
							},
						},
					},
					Continue: true,
				},
				{
					AgentState: &client.AgentState{
						Components: []client.ComponentState{
							{
								ID: "test",
								Units: []client.ComponentUnitState{
									{
										UnitType: client.UnitTypeInput,
										UnitID:   "input",
										State:    client.Configuring,
									},
								},
							},
						},
					},
					Continue: true,
				},
				{
					AgentState: &client.AgentState{
						Components: []client.ComponentState{
							{
								ID: "test",
								Units: []client.ComponentUnitState{
									{
										UnitType: client.UnitTypeInput,
										UnitID:   "input",
										State:    client.Healthy,
									},
									{
										UnitType: client.UnitTypeOutput,
										UnitID:   "other",
										State:    client.Healthy,
									},
								},
							},
						},
					},
					Continue: true,
				},
				{
					AgentState: &client.AgentState{
						Components: []client.ComponentState{
							{
								ID: "test",
								Units: []client.ComponentUnitState{
									{
										UnitType: client.UnitTypeInput,
										UnitID:   "input",
										State:    client.Healthy,
									},
								},
							},
						},
					},
					Continue: false,
				},
			},
		},
		{
			Name: "unit reached callback",
			States: []State{
				{
					Configure: "my config",
					StrictComponents: map[string]ComponentState{
						"test": {
							StrictUnits: map[ComponentUnitKey]ComponentUnitState{
								ComponentUnitKey{UnitType: client.UnitTypeInput, UnitID: "input"}: {
									Reached: func(state *client.ComponentUnitState) bool {
										return state.State == client.Healthy && state.Message == "Specific Message"
									},
								},
							},
						},
					},
				},
			},
			AgentStates: []NextCall{
				{
					AgentState: &client.AgentState{},
					Configure:  "my config",
					Continue:   true,
				},
				{
					AgentState: &client.AgentState{
						Components: []client.ComponentState{
							{
								ID: "test",
							},
						},
					},
					Continue: true,
				},
				{
					AgentState: &client.AgentState{
						Components: []client.ComponentState{
							{
								ID: "test",
								Units: []client.ComponentUnitState{
									{
										UnitType: client.UnitTypeInput,
										UnitID:   "input",
										State:    client.Starting,
									},
								},
							},
						},
					},
					Continue: true,
				},
				{
					AgentState: &client.AgentState{
						Components: []client.ComponentState{
							{
								ID: "test",
								Units: []client.ComponentUnitState{
									{
										UnitType: client.UnitTypeInput,
										UnitID:   "input",
										State:    client.Configuring,
									},
								},
							},
						},
					},
					Continue: true,
				},
				{
					AgentState: &client.AgentState{
						Components: []client.ComponentState{
							{
								ID: "test",
								Units: []client.ComponentUnitState{
									{
										UnitType: client.UnitTypeInput,
										UnitID:   "input",
										State:    client.Healthy,
										Message:  "Not a Specific Message",
									},
								},
							},
						},
					},
					Continue: true,
				},
				{
					AgentState: &client.AgentState{
						Components: []client.ComponentState{
							{
								ID: "wrong-id",
								Units: []client.ComponentUnitState{
									{
										UnitType: client.UnitTypeInput,
										UnitID:   "input",
										State:    client.Healthy,
										Message:  "Specific Message",
									},
								},
							},
						},
					},
					Continue: true,
				},
				{
					AgentState: &client.AgentState{
						Components: []client.ComponentState{
							{
								ID: "test",
								Units: []client.ComponentUnitState{
									{
										UnitType: client.UnitTypeInput,
										UnitID:   "wrong-input",
										State:    client.Healthy,
										Message:  "Specific Message",
									},
								},
							},
						},
					},
					Continue: true,
				},
				{
					AgentState: &client.AgentState{
						Components: []client.ComponentState{
							{
								ID: "test",
								Units: []client.ComponentUnitState{
									{
										UnitType: client.UnitTypeInput,
										UnitID:   "input",
										State:    client.Healthy,
										Message:  "Specific Message",
									},
								},
							},
						},
					},
					Continue: false,
				},
			},
		},
	}

	for _, scenario := range scenarios {
		t.Run(scenario.Name, func(t *testing.T) {
			m, err := newStateMachine(scenario.States)
			if scenario.Err != nil {
				require.Error(t, err)
				require.Equal(t, scenario.Err.Error(), err.Error())
			} else {
				require.NoError(t, err)
			}
			for _, nextCall := range scenario.AgentStates {
				cfg, cont, err := m.next(nextCall.AgentState)
				if nextCall.Err != nil {
					require.Error(t, err)
					require.Equal(t, nextCall.Err.Error(), err.Error())
				} else {
					require.NoError(t, err)
				}
				require.Equal(t, nextCall.Configure, cfg)
				require.Equal(t, nextCall.Continue, cont)
			}
		})
	}
}

func TestStateMachine_Before_After(t *testing.T) {
	firstBefore := false
	firstAfter := false
	secondBefore := false
	secondAfter := false

	states := []State{
		{
			Configure:  "my config",
			AgentState: NewClientState(client.Configuring),
			Before: func() error {
				firstBefore = true
				return nil
			},
			After: func() error {
				firstAfter = true
				return nil
			},
		},
		{
			AgentState: NewClientState(client.Healthy),
			Before: func() error {
				secondBefore = true
				return nil
			},
			After: func() error {
				secondAfter = true
				return nil
			},
		},
	}

	m, err := newStateMachine(states)
	require.NoError(t, err)

	cfg, cont, err := m.next(&client.AgentState{
		State: client.Configuring,
	})
	require.NoError(t, err)
	require.True(t, cont)
	require.Equal(t, "my config", cfg)
	require.True(t, firstBefore)
	require.False(t, firstAfter)

	cfg, cont, err = m.next(&client.AgentState{
		State: client.Configuring,
	})
	require.NoError(t, err)
	require.True(t, cont)
	require.Equal(t, "", cfg)
	require.True(t, firstAfter)
	require.True(t, secondBefore)
	require.False(t, secondAfter)

	cfg, cont, err = m.next(&client.AgentState{
		State: client.Healthy,
	})
	require.NoError(t, err)
	require.False(t, cont)
	require.Equal(t, "", cfg)
	require.True(t, secondAfter)
}
