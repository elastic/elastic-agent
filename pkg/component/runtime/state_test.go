// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package runtime

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/elastic/elastic-agent-client/v7/pkg/proto"

	"github.com/elastic/elastic-agent/pkg/component"
)

// A unit removed from the model and re-added before the component confirms it
// stopped must be expected to run again.
func TestComponentState_UnitReaddedBeforeStopConfirmed(t *testing.T) {
	const keep, flap = "unit-keep", "unit-flap"
	flapKey := ComponentUnitKey{UnitType: client.UnitTypeInput, UnitID: flap}

	newComp := func(unitIDs ...string) *component.Component {
		comp := &component.Component{ID: "fake-default"}
		for _, id := range unitIDs {
			comp.Units = append(comp.Units, component.Unit{
				ID:       id,
				Type:     client.UnitTypeInput,
				LogLevel: client.UnitLogLevelInfo,
				Config:   &proto.UnitExpectedConfig{Id: id, Type: "fake"},
			})
		}
		return comp
	}

	s := newComponentState(newComp(keep, flap))
	// The component reports both units running.
	for k, u := range s.Units {
		u.State, u.unitState = client.UnitStateHealthy, client.UnitStateHealthy
		s.Units[k] = u
	}

	// The unit is removed from the model.
	s.syncExpected(newComp(keep))
	s.syncUnits(newComp(keep))
	require.Equal(t, client.UnitStateStopped, s.expectedUnits[flapKey].state)
	removedIdx := s.expectedUnits[flapKey].configStateIdx

	// The unit is re-added before the component checked in with the stop.
	s.syncExpected(newComp(keep, flap))
	s.syncUnits(newComp(keep, flap))
	assert.Equal(t, client.UnitStateHealthy, s.expectedUnits[flapKey].state,
		"re-added unit must be expected to run")
	assert.Greater(t, s.expectedUnits[flapKey].configStateIdx, removedIdx,
		"re-added unit config must be sent again")

	// The component then reports the unit stopped, from the earlier expected state.
	u := s.Units[flapKey]
	u.unitState = client.UnitStateStopped
	s.Units[flapKey] = u
	s.cleanupStopped()

	_, stillExpected := s.expectedUnits[flapKey]
	assert.True(t, stillExpected, "re-added unit must not be cleaned up")
}
