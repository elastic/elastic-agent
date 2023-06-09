// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package coordinator

import (
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
type StasdfateFetcher interface {
	// State returns the current state of the coordinator.
	State() State
}

type coordinatorOverrideState struct {
	state   agentclient.State
	message string
}

// setRuntimeManagerError updates the error state for the runtime manager.
// Called on the main Coordinator goroutine.
func (c *Coordinator) setRuntimeManagerError(err error) {
	c.runtimeMgrErr = err
	c.stateNeedsRefresh = true
}

// setConfigManagerError updates the error state for the config manager.
// Called on the main Coordinator goroutine.
func (c *Coordinator) setConfigManagerError(err error) {
	c.configMgrErr = err
	c.stateNeedsRefresh = true
}

// setConfigManagerActionsError updates the error state for the config manager actions errors.
// Called on the main Coordinator goroutine.
func (c *Coordinator) setConfigManagerActionsError(err error) {
	c.actionsErr = err
	c.stateNeedsRefresh = true
}

// setVarsManagerError updates the error state for the variables manager.
// Called on the main Coordinator goroutine.
func (c *Coordinator) setVarsManagerError(err error) {
	c.varsMgrErr = err
	c.stateNeedsRefresh = true
}

// SetOverrideState sets the override state, so the Coordinator will report the
// given values instead of its usual internal state. This is used during upgrades.
// Coordinator will forward the overridden state to any state subscribers.
// Callers should follow up with ClearOverrideState as soon as it is safe to do so.
func (c *Coordinator) SetOverrideState(state agentclient.State, message string) {
	c.overrideStateChan <- &coordinatorOverrideState{
		state:   state,
		message: message,
	}
}

// ClearOverrideState clears the override state, reverting to reporting Coordinator's
// real internal state based on the health of its managers.
func (c *Coordinator) ClearOverrideState() {
	c.overrideStateChan <- nil
}

// Forward the current state to the broadcaster and clear the stateNeedsRefresh
// flag. Must be called on the main Coordinator goroutine.
func (c *Coordinator) refreshState() {
	c.stateBroadcaster.Set(c.generateReportableState())
	c.stateNeedsRefresh = false
}

// applyComponentState merges a changed component state into the overall
// Coordinator state.
// Must be called on the main Coordinator goroutine.
func (c *Coordinator) applyComponentState(state runtime.ComponentComponentState) {
	found := false
	for i, other := range c.state.Components {
		if other.Component.ID == state.Component.ID {
			c.state.Components[i] = state
			found = true
			break
		}
	}
	if !found {
		c.state.Components = append(c.state.Components, state)
	}

	// In the case that the component has stopped, it is now removed.
	// Broadcast its stopped state immediately, so subscribers get notified of stopped before removal
	// TODO: is this separation still needed?
	if state.State.State == client.UnitStateStopped {
		c.refreshState()
		for i, other := range c.state.Components {
			if other.Component.ID == state.Component.ID {
				c.state.Components = append(c.state.Components[:i], c.state.Components[i+1:]...)
				break
			}
		}
	}

	c.stateNeedsRefresh = true
}

// generateReportableState aggregates the internal state of the Coordinator
// and its subcomponents for external listeners. The returned state will be
// healthy only if the internal coordinator state.State is healthy and all
// components and units are also healthy (or in ephemeral non-error states).
// Must be called on the main Coordinator goroutine.
func (c *Coordinator) generateReportableState() (s State) {
	s.State = c.state.State
	s.Message = c.state.Message
	s.FleetState = c.state.FleetState
	s.FleetMessage = c.state.FleetMessage
	s.LogLevel = c.state.LogLevel
	s.Components = make([]runtime.ComponentComponentState, len(c.state.Components))
	copy(s.Components, c.state.Components)

	if c.overrideState != nil {
		// state has been overridden due to an action that is occurring
		s.State = c.overrideState.state
		s.Message = c.overrideState.message
	} else if s.State == agentclient.Healthy {
		// if any of the managers are reporting an error then something is wrong
		// or
		// coordinator overall is reported is healthy; in the case any component or unit is not healthy then we report
		// as degraded because we are not fully healthy
		// TODO: We should aggregate these error messages into a readable list
		// instead of only reporting the first one we encounter.
		if c.runtimeMgrErr != nil {
			s.State = agentclient.Failed
			s.Message = c.runtimeMgrErr.Error()
		} else if c.configMgrErr != nil {
			s.State = agentclient.Failed
			s.Message = c.configMgrErr.Error()
		} else if c.actionsErr != nil {
			s.State = agentclient.Failed
			s.Message = c.actionsErr.Error()
		} else if c.varsMgrErr != nil {
			s.State = agentclient.Failed
			s.Message = c.varsMgrErr.Error()
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

/*
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
*/

// setState changes the overall state of the coordinator.
// Must be called on the main Coordinator goroutine.
func (c *Coordinator) setState(state agentclient.State, message string) {
	c.state.State = state
	c.state.Message = message
	c.stateNeedsRefresh = true
}

// setFleetState changes the fleet state of the coordinator.
// Must be called on the main Coordinator goroutine.
func (c *Coordinator) setFleetState(state agentclient.State, message string) {
	c.state.FleetState = state
	c.state.FleetMessage = message
	c.stateNeedsRefresh = true
}

// setLogLevel changes the log level state of the coordinator.
// Must be called on the main Coordinator goroutine.
func (c *Coordinator) setLogLevel(logLevel logp.Level) {
	c.state.LogLevel = logLevel
	c.stateNeedsRefresh = true
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
