// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package testing

import (
	"errors"
	"fmt"

	"github.com/elastic/elastic-agent/pkg/control/v2/client"
)

// NewClientState creates a pointer to a state.
//
// Used to easily define state pointers in the `State` follow.
func NewClientState(state client.State) *client.State {
	return &state
}

// ComponentUnitKey is a composite key to identify a unit by its type and ID.
type ComponentUnitKey struct {
	UnitType client.UnitType
	UnitID   string
}

// String return the string representation.
func (k ComponentUnitKey) String() string {
	return fmt.Sprintf("(%s) %s", k.UnitType, k.UnitID)
}

// ComponentUnitState is the overall state of a unit.
type ComponentUnitState struct {
	// State defines the state at which the unit should be for this state to be reached.
	//
	// If nil then checking that the state matches is skipped, use when the state of the unit
	// is not important to your test.
	State *client.State

	// Reached (if defined) is called instead of using the defined `State` to determine if this state
	// has been reached for this component. Return `true` when the state has been reached, `false` will
	// result in the function being called on each check until `true` is returned.
	//
	// When defined the value set on `State` is ignored.
	Reached func(state *client.ComponentUnitState) bool
}

// Validate ensures correctness of state definition.
func (s *ComponentUnitState) Validate() error {
	if s.Reached == nil && s.State == nil {
		return errors.New("must define Reached if no State defined")
	}
	return nil
}

// ComponentState is the overall state of a component.
type ComponentState struct {
	// State defines the state at which the component should be for this state to be reached.
	//
	// If nil then checking that the state matches is skipped, use when the state of the component
	// is not important to your test.
	State *client.State

	// Units defines the state at which all the units in the component must at least match.
	//
	// When using `Units` over `StrictUnits` it is okay if the component is running other units
	// that are not defined in this mapping. This allows your test to only validate specific units.
	//
	// If nil then checking the units is skipped, use when the state of the units is not important to your test.
	Units map[ComponentUnitKey]ComponentUnitState

	// StrictUnits defines the state at which all the units in the component must equal exactly.
	//
	// If the component is running more units defined even if all the states of the units match those
	// defined here then it is not considered to have reached this state.
	//
	// If nil then strict checking the units is skipped, use when the strict state of the units
	// is not important to your test.
	StrictUnits map[ComponentUnitKey]ComponentUnitState

	// Reached (if defined) is called instead of using the defined `State`, `Units`, and `StrictUnits` above
	// to determine if this state has been reached for this component. Return `true` when the state has been reached,
	// `false` will result in the function being called on each check until `true` is returned.
	//
	// When defined all values set on `State`, `Units`, and `StrictUnits` are ignored.
	Reached func(state *client.ComponentState) bool
}

// Validate ensures correctness of state definition.
func (s *ComponentState) Validate() error {
	if s.Reached == nil && s.State == nil && s.Units == nil && s.StrictUnits == nil {
		return errors.New("must define Reached if no State, Units, or StrictUnits is not defined")
	}
	if s.StrictUnits != nil {
		for key, state := range s.StrictUnits {
			if err := state.Validate(); err != nil {
				return fmt.Errorf("strict unit %s invalid: %w", key, err)
			}
		}
	} else if s.Units != nil {
		for key, state := range s.Units {
			if err := state.Validate(); err != nil {
				return fmt.Errorf("unit %s invalid: %w", key, err)
			}
		}
	}
	return nil
}

// State defines a point in time state for the state machine.
type State struct {
	// Configuration defines the configuration that should be set as soon as this state is next.
	//
	// If no configuration is defined then the previous configuration from the previous states are used.
	Configure string

	// AgentState defines the state at which the Elastic Agent should be for this state to be reached.
	//
	// If nil then checking that the state matches is skipped, use when the overall state of the Elastic Agent
	// is not important to your test.
	AgentState *client.State

	// FleetState defines the state at which the Elastic Agent fleet state should be for this state to be reached.
	//
	// If nil then checking that the state matches is skipped, use when the fleet state of the Elastic Agent
	// is not important to your test.
	FleetState *client.State

	// Components defines the state at which all the components in the running Elastic Agent must at least match.
	//
	// When using `Components` over `StrictComponents` it is okay if the Elastic Agent is running other components
	// that are not defined in this mapping. This allows your test to only validate specific components.
	//
	// If nil then checking the components is skipped, use when the state of the Elastic Agent components
	// is not important to your test.
	Components map[string]ComponentState

	// StrictComponents defines the state at which all the components in the running Elastic Agent must equal exactly.
	//
	// If the Elastic Agent is running more components defined even if all the states of the components match those
	// defined here then it is not considered to have reached this state.
	//
	// If nil then strict checking the components is skipped, use when the strict state of the components
	// is not important to your test.
	StrictComponents map[string]ComponentState

	// Reached (if defined) is called instead of using the defined `AgentState`, `FleetState`, `Components`, and
	// `StrictComponents` above to determine if this state has been reached. Return `true` when the state has been
	// reached, `false` will result in the function being called on each check until `true` is returned.
	//
	// When defined all values set on `AgentState`, `FleetState`, `Components`, and `StrictComponents` are ignored.
	Reached func(*client.AgentState) bool

	// Before is called once when this state is the next state trying to be resolved.
	// This is called before the configuration is sent to the Elastic Agent if `Configuration` is set.
	Before func() error

	// After is called once after this state has been resolved and the next state is going to be tried.
	After func() error
}

// Validate ensures correctness of state definition.
func (s *State) Validate() error {
	if s.Reached == nil && s.AgentState == nil && s.FleetState == nil && s.Components == nil && s.StrictComponents == nil {
		return errors.New("must define Reached if no AgentState, FleetState, Components, or StrictComponents is not defined")
	}
	if s.StrictComponents != nil {
		for key, state := range s.StrictComponents {
			if err := state.Validate(); err != nil {
				return fmt.Errorf("strict component %s invalid: %w", key, err)
			}
		}
	} else if s.Components != nil {
		for key, state := range s.Components {
			if err := state.Validate(); err != nil {
				return fmt.Errorf("component %s invalid: %w", key, err)
			}
		}
	}
	return nil
}

// stateMachine tracks which state in the machine is active and if the machine has been successful in reaching the end.
type stateMachine struct {
	current int
	states  []State
}

func newStateMachine(states []State) (*stateMachine, error) {
	if len(states) == 0 {
		return nil, errors.New("must defined at least 1 state")
	}
	cfg := false
	for idx, state := range states {
		if err := state.Validate(); err != nil {
			return nil, fmt.Errorf("state %d invalid: %w", idx, err)
		}
		if state.Configure != "" {
			cfg = true
		}
	}
	if !cfg {
		return nil, errors.New("at least one state must define a configuration")
	}
	return &stateMachine{
		current: -1,
		states:  states,
	}, nil
}

func (sm *stateMachine) next(agentState *client.AgentState) (string, bool, error) {
	if sm.current >= len(sm.states) {
		// already made it to the end, should be stopped
		return "", false, nil
	}
	var state State
	var reached bool
	if sm.current == -1 {
		// immediately go to the first state
		reached = true
	} else {
		state = sm.states[sm.current]
		reached = stateReached(state, agentState)
	}
	if reached {
		if state.After != nil {
			if err := state.After(); err != nil {
				return "", false, fmt.Errorf("failed to perform After on state %d: %w", sm.current, err)
			}
		}
		sm.current++
		if sm.current >= len(sm.states) {
			// finished the last state; should be stopped
			return "", false, nil
		}
		next := sm.states[sm.current]
		if next.Before != nil {
			if err := next.Before(); err != nil {
				return "", false, fmt.Errorf("failed to perform Before on state %d: %w", sm.current, err)
			}
		}
		if next.Configure != "" {
			// state has a configuration, needs to be sent before agentState matching can be performed
			return next.Configure, true, nil
		}
		// no configuration on this state; so we can determine if this next state has already been reached as well
		return sm.next(agentState)
	}
	return "", true, nil
}

func stateReached(state State, agentState *client.AgentState) bool {
	if agentState == nil {
		return false
	}
	if state.Reached != nil {
		return state.Reached(agentState)
	}
	if state.AgentState != nil {
		if *state.AgentState != agentState.State {
			return false
		}
	}
	if state.FleetState != nil {
		if *state.FleetState != agentState.FleetState {
			return false
		}
	}
	if state.StrictComponents != nil {
		if !stateComponentsReached(state.StrictComponents, agentState.Components, true) {
			return false
		}
	} else if state.Components != nil {
		if !stateComponentsReached(state.Components, agentState.Components, false) {
			return false
		}
	}
	return true
}

func stateComponentsReached(components map[string]ComponentState, agentComponents []client.ComponentState, strict bool) bool {
	if strict && len(components) != len(agentComponents) {
		return false
	}
	found := make(map[string]bool)
	for _, agentComp := range agentComponents {
		state, ok := components[agentComp.ID]
		if !ok {
			if strict {
				// component that should not be present at this state
				return false
			}
			// not in strict mode so don't care about this components state
			continue
		}
		found[agentComp.ID] = true
		if !stateComponentReached(state, &agentComp) {
			return false
		}
	}
	for compID, _ := range components {
		_, ok := found[compID]
		if !ok {
			// was not found
			return false
		}
	}
	return true
}

func stateComponentReached(state ComponentState, agentComp *client.ComponentState) bool {
	if state.Reached != nil {
		return state.Reached(agentComp)
	}
	if state.State != nil {
		if *state.State != agentComp.State {
			return false
		}
	}
	if state.StrictUnits != nil {
		if !stateComponentUnitsReached(state.StrictUnits, agentComp.Units, true) {
			return false
		}
	} else if state.Units != nil {
		if !stateComponentUnitsReached(state.Units, agentComp.Units, false) {
			return false
		}
	}
	return true
}

func stateComponentUnitsReached(units map[ComponentUnitKey]ComponentUnitState, compUnits []client.ComponentUnitState, strict bool) bool {
	if strict && len(units) != len(compUnits) {
		return false
	}
	found := make(map[ComponentUnitKey]bool)
	for _, compUnit := range compUnits {
		key := ComponentUnitKey{UnitType: compUnit.UnitType, UnitID: compUnit.UnitID}
		state, ok := units[key]
		if !ok {
			if strict {
				// component that should not be present at this state
				return false
			}
			// not in strict mode so don't care about this components state
			continue
		}
		found[key] = true
		if !stateComponentUnitReached(state, &compUnit) {
			return false
		}
	}
	for key, _ := range units {
		_, ok := found[key]
		if !ok {
			// was not found
			return false
		}
	}
	return true
}

func stateComponentUnitReached(state ComponentUnitState, agentUnit *client.ComponentUnitState) bool {
	if state.Reached != nil {
		return state.Reached(agentUnit)
	}
	if state.State != nil {
		if *state.State != agentUnit.State {
			return false
		}
	}
	return true
}
