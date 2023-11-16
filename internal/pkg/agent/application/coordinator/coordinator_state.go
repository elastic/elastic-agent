// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package coordinator

import (
	"fmt"

	agentclient "github.com/elastic/elastic-agent/pkg/control/v2/client"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/elastic-agent/pkg/component/runtime"
)

// State provides the current state of the coordinator along with all the current states of components and units.
type State struct {
	// An overall state produced by aggregating
	State   agentclient.State `yaml:"state"`
	Message string            `yaml:"message"`

	// The state of the Coordinator
	CoordinatorState   agentclient.State `yaml:"coordinator_state"`
	CoordinatorMessage string            `yaml:"coordinator_message"`

	// The state of the
	FleetState   agentclient.State `yaml:"fleet_state"`
	FleetMessage string            `yaml:"fleet_message"`

	Components []runtime.ComponentComponentState `yaml:"components"`
	LogLevel   logp.Level                        `yaml:"log_level"`
}

type coordinatorOverrideState struct {
	state   agentclient.State
	message string
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

<<<<<<< HEAD
// setRuntimeManagerError updates the error state for the runtime manager.
=======
// SetUpgradeDetails sets upgrade details. This is used during upgrades.
func (c *Coordinator) SetUpgradeDetails(upgradeDetails *details.Details) {
	c.upgradeDetailsChan <- upgradeDetails
}

// setRuntimeUpdateError reports a failed policy update in the runtime manager.
>>>>>>> 112f618969 (Rework runtime manager updates to block the coordinator less (#3747))
// Called on the main Coordinator goroutine.
func (c *Coordinator) setRuntimeUpdateError(err error) {
	c.runtimeUpdateErr = err
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

// setConfigError updates the error state for converting an incoming policy
// into an AST.
// Called on the main Coordinator goroutine.
func (c *Coordinator) setConfigError(err error) {
	c.configErr = err
	c.stateNeedsRefresh = true
}

// setComponentGenError updates the error state for generating a component
// model from an AST and variables.
// Called on the main Coordinator goroutine.
func (c *Coordinator) setComponentGenError(err error) {
	c.componentGenErr = err
	c.stateNeedsRefresh = true
}

// setOverrideState is the internal helper to set the override state and
// set stateNeedsRefresh.
// Must be called on the main Coordinator goroutine.
func (c *Coordinator) setOverrideState(overrideState *coordinatorOverrideState) {
	c.overrideState = overrideState
	c.stateNeedsRefresh = true
}

// Forward the current state to the broadcaster and clear the stateNeedsRefresh
// flag. Must be called on the main Coordinator goroutine.
func (c *Coordinator) refreshState() {
	c.stateBroadcaster.InputChan <- c.generateReportableState()
	c.stateNeedsRefresh = false
}

// applyComponentState merges a changed component state into the overall
// Coordinator state and sets stateNeedsRefresh.
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
	s.CoordinatorState = c.state.CoordinatorState
	s.CoordinatorMessage = c.state.CoordinatorMessage
	s.FleetState = c.state.FleetState
	s.FleetMessage = c.state.FleetMessage
	s.LogLevel = c.state.LogLevel
	s.Components = make([]runtime.ComponentComponentState, len(c.state.Components))
	copy(s.Components, c.state.Components)

	// Ordering of state aggregation:
	// - Override state, if present
	// - Errors applying the configured policy (report Failed)
	// - Errors reported by managers (report Failed)
	// - Errors in component/unit state (report Degraded)
	if c.overrideState != nil {
		// state has been overridden by an upgrade in progress
		s.State = c.overrideState.state
		s.Message = c.overrideState.message
	} else if c.configErr != nil {
		s.State = agentclient.Failed
		s.Message = fmt.Sprintf("Invalid policy: %s", c.configErr.Error())
	} else if c.componentGenErr != nil {
		s.State = agentclient.Failed
		s.Message = fmt.Sprintf("Invalid component model: %s", c.componentGenErr.Error())
	} else if c.runtimeUpdateErr != nil {
		s.State = agentclient.Failed
		s.Message = fmt.Sprintf("Runtime update failed: %s", c.runtimeUpdateErr.Error())
	} else if c.configMgrErr != nil {
		s.State = agentclient.Failed
		s.Message = fmt.Sprintf("Config manager: %s", c.configMgrErr.Error())
	} else if c.actionsErr != nil {
		s.State = agentclient.Failed
		s.Message = fmt.Sprintf("Actions: %s", c.actionsErr.Error())
	} else if c.varsMgrErr != nil {
		s.State = agentclient.Failed
		s.Message = fmt.Sprintf("Vars manager: %s", c.varsMgrErr.Error())
	} else if hasState(s.Components, client.UnitStateFailed) {
		s.State = agentclient.Degraded
		s.Message = "1 or more components/units in a failed state"
	} else if hasState(s.Components, client.UnitStateDegraded) {
		s.State = agentclient.Degraded
		s.Message = "1 or more components/units in a degraded state"
	} else {
		// If no error conditions apply, the global state inherits the current
		// Coordinator state.
		s.State = s.CoordinatorState
		s.Message = s.CoordinatorMessage
	}
	return s
}

// setCoordinatorState changes the overall state of the coordinator.
// Must be called on the main Coordinator goroutine.
func (c *Coordinator) setCoordinatorState(state agentclient.State, message string) {
	c.state.CoordinatorState = state
	c.state.CoordinatorMessage = message
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

// Returns true if any component in the given list, or any unit in one of
// those components, matches the given state.
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
