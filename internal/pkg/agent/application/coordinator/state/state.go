// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package state

import (
	"context"
	"reflect"
	"sync"

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

	// StateSubscriptions sent to subscribeChan will receive state updates from
	// stateReporter until their context is cancelled.
	subscribeChan chan StateSubscription

	// (*CoordinatorState).changed sends on this channel to notify stateReporter
	// when the state changes.
	stateChangedChan chan struct{}
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
	cs := &CoordinatorState{
		state:        state,
		message:      msg,
		fleetState:   fleetState,
		fleetMessage: fleetMsg,
		logLevel:     logLevel,

		// subscribeChan is synchronous: once Subscribe returns, the caller is
		// guaranteed to be included in future state change notifications.
		subscribeChan: make(chan StateSubscription),

		// stateChangedChan is asynchronous with buffer size 1: this guarantees
		// that state changes will propagate but multiple simultaneous changes
		// will not accumulate.
		stateChangedChan: make(chan struct{}, 1),
	}
	go cs.stateReporter()
	return cs
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
	// We need to claim all three mutexes simultaneously, otherwise we may
	// collect inconsistent states from the different components if one of them
	// changes during this function call.
	cs.mx.RLock()
	cs.compStatesMx.RLock()
	cs.mgrMx.RLock()
	defer cs.mx.RUnlock()
	defer cs.compStatesMx.RUnlock()
	defer cs.mgrMx.RUnlock()

	s.State = cs.state
	s.Message = cs.message
	s.FleetState = cs.fleetState
	s.FleetMessage = cs.fleetMessage
	s.LogLevel = cs.logLevel
	overrideState := cs.overrideState

	// copy component states for PIT
	compStates := make([]runtime.ComponentComponentState, len(cs.compStates))
	copy(compStates, cs.compStates)
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
func (cs *CoordinatorState) Subscribe(ctx context.Context) StateSubscription {
	sub := newStateSubscription(ctx)
	cs.subscribeChan <- sub
	return sub
}

func (cs *CoordinatorState) changed() {
	// Try to send to stateChangedChan but don't block -- if its buffer is full
	// then an update is already pending, and the changes we're reporting will
	// be included.
	select {
	case cs.stateChangedChan <- struct{}{}:
	default:
	}
}

func (cs *CoordinatorState) stateReporter() {
	var subscribers []StateSubscription
	// We support a variable number of subscribers and we don't want any of them
	// to block each other or the CoordinatorState as a whole, so we need to
	// listen with reflect.Select, which selects on an array of cases.
	// Unfortunately this means we need to track the active select cases
	// ourselves, including their position in the array.
	//
	// The ordering we use is:
	// - first, the listener on subscribeChan
	// - second, the listener on stateChangedChan
	// - after that, two cases for each subscriber, in the same order as the
	//   subscribers array: first its done channel, then its listener channel.
	//
	// All subscribers are included in the array of select cases even when some
	// have already been updated, that way we don't need to worry about the
	// order changing. Instead, subscribers that have already been updated have
	// the listener channel of their select case set to nil.
	selectCases := []reflect.SelectCase{
		{
			Dir:  reflect.SelectRecv,
			Chan: reflect.ValueOf(cs.subscribeChan),
		},
		{
			Dir:  reflect.SelectRecv,
			Chan: reflect.ValueOf(cs.stateChangedChan),
		},
	}
	const newSubscriberIndex = 0
	const stateChangedIndex = 1
	const firstSubscriberIndex = 2

	currentState := cs.State()

	// resetListeners is called when a state change notification arrives, to
	// reactivate the listener channels of all subscribers and update their
	// select case to the new state value.
	resetListeners := func() {
		currentState = cs.State()
		for i, subscriber := range subscribers {
			listenerIndex := firstSubscriberIndex + 2*i + 1
			selectCases[listenerIndex].Chan = reflect.ValueOf(subscriber.ch)
			selectCases[listenerIndex].Send = reflect.ValueOf(currentState)
		}
	}

	// addSubscriber is a helper to add a new subscriber and its select
	// cases to our lists.
	addSubscriber := func(subscriber StateSubscription) {
		subscribers = append(subscribers, subscriber)
		selectCases = append(selectCases,
			// Add a select case receiving from the subscriber's done channel
			reflect.SelectCase{
				Dir:  reflect.SelectRecv,
				Chan: reflect.ValueOf(subscriber.ctx.Done()),
			},
			// Add a select case sending to the subscriber's listener channel
			reflect.SelectCase{
				Dir:  reflect.SelectSend,
				Chan: reflect.ValueOf(subscriber.ch),
			})
	}

	for {
		// Always try a standalone receive on the state changed channel first, so
		// it gets priority over other updates.
		select {
		case <-cs.stateChangedChan:
			resetListeners()
		default:
		}

		chosen, value, _ := reflect.Select(selectCases)
		if chosen == stateChangedIndex {
			resetListeners()
		} else if chosen == newSubscriberIndex {
			subscriber, ok := value.Interface().(StateSubscription)
			if ok {
				addSubscriber(subscriber)
			}
		} else {
			subscriberIndex := (chosen - firstSubscriberIndex) / 2
			if (chosen-firstSubscriberIndex)%2 == 0 {
				// The subscriber's done channel has been closed, remove
				// them from our lists
				subscribers = append(
					subscribers[:subscriberIndex],
					subscribers[subscriberIndex+1:]...)
				selectCases = append(
					selectCases[:chosen],
					selectCases[chosen+2:]...)
			} else {
				// We successfully sent a state update to this subscriber, turn off
				// its listener channel until we receive a new state change.
				selectCases[chosen].Chan = reflect.ValueOf(nil)
			}
		}
	}
}

// StateSubscription provides a channel for notifications of state changes.
type StateSubscription struct {
	// When this context expires the subscription will be cancelled by
	// CoordinatorState.stateReporter.
	ctx context.Context

	// When the state changes, the new state will be sent to this channel.
	// If multiple state changes accumulate before the receiver reads from this
	// channel, then only the most recent one will be sent.
	ch chan State
}

func newStateSubscription(ctx context.Context) StateSubscription {
	return StateSubscription{
		ctx: ctx,
		// The subscriber channel is unbuffered so it always gets the most recent
		// state at the time it receives from the channel.
		ch: make(chan State),
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
