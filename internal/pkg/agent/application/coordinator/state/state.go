// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package state

import (
	"context"
	"sync"
	"time"

	agentclient "github.com/elastic/elastic-agent/pkg/control/v2/client"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/elastic-agent/pkg/component/runtime"
)

// State provides the current state of the coordinator along with all the current states of components and units.
type State struct {
	State        agentclient.State                 `yaml:"state"`
	Message      string                            `yaml:"message"`
	FleetState   agentclient.State                 `yaml:"fleet_state"`
	FleetMessage string                            `yaml:"fleet_message"`
	Components   []runtime.ComponentComponentState `yaml:"components"`
	LogLevel     logp.Level                        `yaml:"log_level"`
}

// StateFetcher provides an interface to fetch the current state of the coordinator.
type StateFetcher interface {
	// State returns the current state of the coordinator.
	State() State
}

type CoordinatorState struct {
	mx            sync.RWMutex
	state         agentclient.State
	message       string
	fleetState    agentclient.State
	fleetMessage  string
	logLevel      logp.Level
	overrideState *coordinatorOverrideState

	compStatesMx sync.RWMutex
	compStates   []runtime.ComponentComponentState

	mgrMx         sync.RWMutex
	runtimeMgrErr error
	configMgrErr  error
	actionsErr    error
	varsMgrErr    error

	subMx     sync.RWMutex
	subscribe []*StateSubscription
}

type coordinatorOverrideState struct {
	state   agentclient.State
	message string
}

type stateSetter struct {
	state        *agentclient.State
	message      *string
	fleetState   *agentclient.State
	fleetMessage *string
	logLevel     *logp.Level
}

type stateSetterOpt func(ss *stateSetter)

// NewCoordinatorState creates the coordinator state manager.
func NewCoordinatorState(state agentclient.State, msg string, fleetState agentclient.State, fleetMsg string, logLevel logp.Level) *CoordinatorState {
	return &CoordinatorState{
		state:        state,
		message:      msg,
		fleetState:   fleetState,
		fleetMessage: fleetMsg,
		logLevel:     logLevel,
	}
}

// UpdateState updates the state triggering a change notification to subscribers.
func (cs *CoordinatorState) UpdateState(setters ...stateSetterOpt) {
	var setter stateSetter
	for _, ss := range setters {
		ss(&setter)
	}

	cs.mx.Lock()
	if setter.state != nil {
		cs.state = *setter.state
	}
	if setter.message != nil {
		cs.message = *setter.message
	}
	if setter.fleetState != nil {
		cs.fleetState = *setter.fleetState
	}
	if setter.fleetMessage != nil {
		cs.fleetMessage = *setter.fleetMessage
	}
	if setter.logLevel != nil {
		cs.logLevel = *setter.logLevel
	}
	cs.mx.Unlock()
	cs.changed()
}

// SetRuntimeManagerError updates the error state for the runtime manager.
func (cs *CoordinatorState) SetRuntimeManagerError(err error) {
	cs.mgrMx.Lock()
	cs.runtimeMgrErr = err
	cs.mgrMx.Unlock()
	cs.changed()
}

// SetConfigManagerError updates the error state for the config manager.
func (cs *CoordinatorState) SetConfigManagerError(err error) {
	cs.mgrMx.Lock()
	cs.configMgrErr = err
	cs.mgrMx.Unlock()
	cs.changed()
}

// SetConfigManagerActionsError updates the error state for the config manager actions errors.
func (cs *CoordinatorState) SetConfigManagerActionsError(err error) {
	cs.mgrMx.Lock()
	cs.actionsErr = err
	cs.mgrMx.Unlock()
	cs.changed()
}

// SetVarsManagerError updates the error state for the variables manager.
func (cs *CoordinatorState) SetVarsManagerError(err error) {
	cs.mgrMx.Lock()
	cs.varsMgrErr = err
	cs.mgrMx.Unlock()
	cs.changed()
}

// SetOverrideState sets the override state triggering a change notification to subscribers.
func (cs *CoordinatorState) SetOverrideState(state agentclient.State, message string) {
	cs.mx.Lock()
	cs.overrideState = &coordinatorOverrideState{
		state:   state,
		message: message,
	}
	cs.mx.Unlock()
	cs.changed()
}

// ClearOverrideState clears the override state triggering a change notification to subscribers.
func (cs *CoordinatorState) ClearOverrideState() {
	cs.mx.Lock()
	cs.overrideState = nil
	cs.mx.Unlock()
	cs.changed()
}

// UpdateComponentState updates the component state triggering a change notification to subscribers.
func (cs *CoordinatorState) UpdateComponentState(state runtime.ComponentComponentState) {
	cs.compStatesMx.Lock()
	found := false
	for i, other := range cs.compStates {
		if other.Component.ID == state.Component.ID {
			cs.compStates[i] = state
			found = true
			break
		}
	}
	if !found {
		cs.compStates = append(cs.compStates, state)
	}
	cs.compStatesMx.Unlock()
	cs.changed()

	// in the case that the component has stopped, it is now removed
	// this is done after the call to `changed` so subscribers get notified of stopped before removal
	if state.State.State == client.UnitStateStopped {
		cs.compStatesMx.Lock()
		for i, other := range cs.compStates {
			if other.Component.ID == state.Component.ID {
				cs.compStates = append(cs.compStates[:i], cs.compStates[i+1:]...)
				break
			}
		}
		cs.compStatesMx.Unlock()
		cs.changed()
	}
}

// State returns the current state for the coordinator.
func (cs *CoordinatorState) State() (s State) {
	cs.mx.RLock()
	s.State = cs.state
	s.Message = cs.message
	s.FleetState = cs.fleetState
	s.FleetMessage = cs.fleetMessage
	s.LogLevel = cs.logLevel
	overrideState := cs.overrideState
	cs.mx.RUnlock()

	// copy component states for PIT
	cs.compStatesMx.RLock()
	compStates := make([]runtime.ComponentComponentState, len(cs.compStates))
	copy(compStates, cs.compStates)
	cs.compStatesMx.RUnlock()
	s.Components = compStates

	if overrideState != nil {
		// state has been overridden due to an action that is occurring
		s.State = overrideState.state
		s.Message = overrideState.message
	} else if s.State == agentclient.Healthy {
		// if any of the managers are reporting an error then something is wrong
		// or
		// coordinator overall is reported is healthy; in the case any component or unit is not healthy then we report
		// as degraded because we are not fully healthy
		cs.mgrMx.RLock()
		defer cs.mgrMx.RUnlock()
		if cs.runtimeMgrErr != nil {
			s.State = agentclient.Failed
			s.Message = cs.runtimeMgrErr.Error()
		} else if cs.configMgrErr != nil {
			s.State = agentclient.Failed
			s.Message = cs.configMgrErr.Error()
		} else if cs.actionsErr != nil {
			s.State = agentclient.Failed
			s.Message = cs.actionsErr.Error()
		} else if cs.varsMgrErr != nil {
			s.State = agentclient.Failed
			s.Message = cs.varsMgrErr.Error()
		} else if hasState(s.Components, client.UnitStateFailed) {
			s.State = agentclient.Degraded
			s.Message = "1 or more components/units in a failed state"
		} else if hasState(s.Components, client.UnitStateDegraded) {
			s.State = agentclient.Degraded
			s.Message = "1 or more components/units in a degraded state"
		}
	}
	return s
}

// Subscribe subscribes to changes in the coordinator state.
//
// This provides the current state at the time of first subscription. Cancelling the context
// results in the subscription being unsubscribed.
//
// Note: Not reading from a subscription channel will cause the Coordinator to block.
func (cs *CoordinatorState) Subscribe(ctx context.Context) *StateSubscription {
	sub := newStateSubscription(ctx, cs)

	// send initial state
	state := cs.State()
	go func() {
		select {
		case <-ctx.Done():
			return
		case sub.ch <- state:
		}
	}()

	// add subscription for future changes
	cs.subMx.Lock()
	cs.subscribe = append(cs.subscribe, sub)
	cs.subMx.Unlock()

	go func() {
		<-ctx.Done()

		// unsubscribe
		cs.subMx.Lock()
		defer cs.subMx.Unlock()
		for i, s := range cs.subscribe {
			if sub == s {
				cs.subscribe = append(cs.subscribe[:i], cs.subscribe[i+1:]...)
				return
			}
		}
	}()

	return sub
}

func (cs *CoordinatorState) changed() {
	cs.sendState(cs.State())
}

func (cs *CoordinatorState) sendState(state State) {
	cs.subMx.RLock()
	defer cs.subMx.RUnlock()

	send := func(sub *StateSubscription) {
		t := time.NewTimer(time.Second)
		defer t.Stop()
		select {
		case <-sub.ctx.Done():
		case sub.ch <- state:
		case <-t.C:
			// subscriber didn't read from the channel after 1 second; so we unblock
		}
	}

	for _, sub := range cs.subscribe {
		send(sub)
	}
}

// StateSubscription provides a channel for notifications of state changes.
type StateSubscription struct {
	ctx context.Context
	cs  *CoordinatorState
	ch  chan State
}

func newStateSubscription(ctx context.Context, cs *CoordinatorState) *StateSubscription {
	return &StateSubscription{
		ctx: ctx,
		cs:  cs,
		ch:  make(chan State),
	}
}

// Ch provides the channel to get state changes.
func (s *StateSubscription) Ch() <-chan State {
	return s.ch
}

// WithState changes the overall state of the coordinator.
func WithState(state agentclient.State, message string) stateSetterOpt {
	return func(ss *stateSetter) {
		ss.state = &state
		ss.message = &message
	}
}

// WithFleetState changes the fleet state of the coordinator.
func WithFleetState(state agentclient.State, message string) stateSetterOpt {
	return func(ss *stateSetter) {
		ss.fleetState = &state
		ss.fleetMessage = &message
	}
}

// WithLogLevel changes the log level state of the coordinator.
func WithLogLevel(logLevel logp.Level) stateSetterOpt {
	return func(ss *stateSetter) {
		ss.logLevel = &logLevel
	}
}

func hasState(components []runtime.ComponentComponentState, state client.UnitState) bool {
	for _, comp := range components {
		if comp.State.State == state {
			return true
		}
		for _, unit := range comp.State.Units {
			if unit.State == state {
				return true
			}
		}
	}
	return false
}
