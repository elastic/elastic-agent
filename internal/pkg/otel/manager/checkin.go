// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package manager

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/elastic/elastic-agent/pkg/component/runtime"
)

const (
	// receiverCheckinPeriod is how often the receivers of components with control
	// protocol units must check in, the same as for beat processes.
	receiverCheckinPeriod = 30 * time.Second
	// maxReceiverCheckinMisses is how many check-ins such a receiver can miss
	// before its component fails, the same as for beat processes.
	maxReceiverCheckinMisses = 3
)

// The receivers of components with control protocol units get their units from
// the unit server, and report their status through the collector. A receiver
// that doesn't check in doesn't get its units, which its status can't show, so
// missed check-ins are reported the way the runtime manager reports them for
// beat processes: a component whose receiver missed a check-in is degraded, and
// one whose receiver missed maxReceiverCheckinMisses check-ins fails, with all
// its units.

// receiverCheckinPeriod returns the period in which receivers that get units
// from the unit server must check in.
func (m *OTelManager) receiverCheckinPeriod() time.Duration {
	if m.checkinPeriod <= 0 {
		return receiverCheckinPeriod
	}
	return m.checkinPeriod
}

// updateMissedCheckins updates how many check-ins the receiver of each component
// with control protocol units missed, and returns the components for which that
// changed.
func (m *OTelManager) updateMissedCheckins() []string {
	if m.unitServer == nil {
		return nil
	}
	missedCheckins := make(map[string]int)
	var changed []string
	for _, comp := range m.components {
		if !comp.UsesControlProtocolUnits() {
			continue
		}
		missed, ok := m.unitServer.MissedCheckins(comp.ID, m.receiverCheckinPeriod())
		if !ok {
			continue
		}
		missed = min(missed, maxReceiverCheckinMisses)
		if missed > 0 {
			missedCheckins[comp.ID] = missed
		}
		if m.missedCheckins[comp.ID] != missed {
			changed = append(changed, comp.ID)
		}
	}
	for id := range m.missedCheckins {
		if _, ok := missedCheckins[id]; !ok && !slices.Contains(changed, id) {
			changed = append(changed, id)
		}
	}
	m.missedCheckins = missedCheckins
	return changed
}

// reportMissedCheckins reports the components whose receivers missed a
// different number of check-ins since the last time. It's called periodically,
// as the collector reports no status changes for a receiver that doesn't check
// in.
func (m *OTelManager) reportMissedCheckins(ctx context.Context) {
	var updates []runtime.ComponentComponentState
	for _, id := range m.updateMissedCheckins() {
		if _, ok := m.currentComponentStates[id]; !ok {
			continue
		}
		collectorState, ok := m.collectorComponentStates[id]
		if !ok {
			continue
		}
		state := m.withMissedCheckins(collectorState)
		m.currentComponentStates[id] = state
		updates = append(updates, state)
	}
	if len(updates) > 0 {
		m.reportComponentStateUpdates(ctx, updates)
	}
}

// withMissedCheckins returns the state of a component as reported by the
// collector, updated with the check-ins its receiver missed.
func (m *OTelManager) withMissedCheckins(compState runtime.ComponentComponentState) runtime.ComponentComponentState {
	missed := m.missedCheckins[compState.Component.ID]
	state := compState.State
	if missed == 0 || state.State == client.UnitStateStopping || state.State == client.UnitStateStopped {
		return compState
	}

	checkins := "1 check-in"
	if missed > 1 {
		checkins = fmt.Sprintf("%d check-ins", missed)
	}
	reason := ""
	if m.unitServerErr != nil {
		reason = fmt.Sprintf(", as the agent failed to start serving its units: %v", m.unitServerErr)
	}

	if missed < maxReceiverCheckinMisses {
		// As for beat processes, only the component is degraded, as its units may
		// still be running.
		if state.State == client.UnitStateStarting || state.State == client.UnitStateConfiguring || state.State == client.UnitStateHealthy {
			state.State = client.UnitStateDegraded
			state.Message = fmt.Sprintf("Degraded: the receiver missed %s%s", checkins, reason)
		}
	} else {
		// The receiver doesn't get unit changes, so none of its units is known to
		// be running as expected.
		message := fmt.Sprintf("Failed: the receiver missed %s%s", checkins, reason)
		state.State = client.UnitStateFailed
		state.Message = message
		units := make(map[runtime.ComponentUnitKey]runtime.ComponentUnitState, len(compState.Component.Units))
		for _, unit := range compState.Component.Units {
			key := runtime.ComponentUnitKey{UnitID: unit.ID, UnitType: unit.Type}
			units[key] = runtime.ComponentUnitState{State: client.UnitStateFailed, Message: message}
		}
		state.Units = units
	}
	compState.State = state
	return compState
}
