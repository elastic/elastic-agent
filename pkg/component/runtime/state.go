// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package runtime

import (
	"errors"
	"fmt"
	"reflect"

	gproto "google.golang.org/protobuf/proto"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/elastic/elastic-agent-client/v7/pkg/proto"
	"github.com/elastic/elastic-agent/pkg/component"
)

const (
	startingMsg = "Starting"
	stoppedMsg  = "Stopped"
	unknownMsg  = "Failed: reported unit is unknown"
	missingMsg  = "Failed: not reported in check-in"
)

// ComponentUnitState is the state for a unit running in a component.
type ComponentUnitState struct {
	State   client.UnitState       `yaml:"state"`
	Message string                 `yaml:"message"`
	Payload map[string]interface{} `yaml:"payload,omitempty"`

	// internal
	unitState      client.UnitState
	unitMessage    string
	unitPayload    map[string]interface{}
	configStateIdx uint64
	err            error
}

// ComponentUnitKey is a composite key to identify a unit by its type and ID.
type ComponentUnitKey struct {
	UnitType client.UnitType
	UnitID   string
}

// MarshalYAML implements the Marshaller interface for the componentUnitKey
func (key ComponentUnitKey) MarshalYAML() (interface{}, error) {
	return fmt.Sprintf("%s-%s", key.UnitType.String(), key.UnitID), nil
}

// ComponentVersionInfo provides version information reported by the component.
type ComponentVersionInfo struct {
	// Name of the binary.
	Name string `yaml:"name"`
	// Version of the binary.
	Version string `yaml:"version"`
	// Additional metadata about the binary.
	Meta map[string]string `yaml:"meta,omitempty"`
}

// ComponentState is the overall state of the component.
type ComponentState struct {
	State   client.UnitState `yaml:"state"`
	Message string           `yaml:"message"`

	Units map[ComponentUnitKey]ComponentUnitState `yaml:"units"`

	// We don't serialize the Features field as YAML so it doesn't show up
	// in the diagnostics-generated state.yaml file, keeping it concise.
	Features    *proto.Features `yaml:"-"`
	FeaturesIdx uint64          `yaml:"features_idx"`

	Component    *proto.Component `yaml:"component,omitempty"`
	ComponentIdx uint64           `yaml:"component_idx"`

	VersionInfo ComponentVersionInfo `yaml:"version_info"`

	// internal
	expectedUnits map[ComponentUnitKey]expectedUnitState

	expectedFeatures    *proto.Features
	expectedFeaturesIdx uint64

	expectedComponent    *proto.Component
	expectedComponentIdx uint64
}

// expectedUnitState is the expected state of a unit.
type expectedUnitState struct {
	state          client.UnitState
	configStateIdx uint64
	config         *proto.UnitExpectedConfig
	err            error
	logLevel       client.UnitLogLevel
}

func newComponentState(comp *component.Component) (s ComponentState) {
	s.State = client.UnitStateStarting
	s.Message = startingMsg
	s.Units = make(map[ComponentUnitKey]ComponentUnitState)
	s.expectedUnits = make(map[ComponentUnitKey]expectedUnitState)
	s.expectedFeaturesIdx = 1
	s.expectedComponentIdx = 1

	s.syncComponent(comp)
	return s
}

// Copy returns a copy of the structure.
func (s *ComponentState) Copy() (c ComponentState) {
	c = *s
	c.Units = make(map[ComponentUnitKey]ComponentUnitState)
	for k, v := range s.Units {
		c.Units[k] = v
	}
	c.expectedUnits = make(map[ComponentUnitKey]expectedUnitState)
	for k, v := range s.expectedUnits {
		c.expectedUnits[k] = v
	}

	c.Features = s.Features
	c.FeaturesIdx = s.FeaturesIdx
	c.expectedFeatures = s.expectedFeatures
	c.expectedFeaturesIdx = s.expectedFeaturesIdx

	c.Component = s.Component
	c.ComponentIdx = s.ComponentIdx
	c.expectedComponent = s.expectedComponent
	c.expectedComponentIdx = s.expectedComponentIdx

	return c
}

func (s *ComponentState) syncComponent(comp *component.Component) bool {
	changed := s.syncExpected(comp)
	s.syncUnits(comp)
	if changed {
		return true
	}
	return s.unsettled()
}

func (s *ComponentState) syncExpected(comp *component.Component) bool {
	changed := false
	touched := make(map[ComponentUnitKey]bool)

	for _, unit := range comp.Units {
		key := ComponentUnitKey{
			UnitType: unit.Type,
			UnitID:   unit.ID,
		}

		touched[key] = true
		existing, ok := s.expectedUnits[key]
		if ok {
			if existing.logLevel != unit.LogLevel {
				existing.logLevel = unit.LogLevel
				changed = true
			}
			if !gproto.Equal(existing.config, unit.Config) {
				existing.config = unit.Config
				existing.configStateIdx++
				changed = true
			}
		} else {
			existing.state = client.UnitStateHealthy
			existing.logLevel = unit.LogLevel
			existing.config = unit.Config
			existing.configStateIdx = 1
			changed = true
		}

		if !errors.Is(existing.err, unit.Err) {
			existing.err = unit.Err
			if existing.err != nil {
				existing.state = client.UnitStateFailed
			}
			changed = true
		}

		s.expectedUnits[key] = existing
	}

	for key, unit := range s.expectedUnits {
		_, ok := touched[key]
		if !ok {
			if unit.state != client.UnitStateStopped {
				unit.state = client.UnitStateStopped
				changed = true

				// unit is a copy and must be set back into the map
				s.expectedUnits[key] = unit
			}
		}
	}

	if !gproto.Equal(s.expectedFeatures, comp.Features) {
		changed = true
		s.expectedFeaturesIdx++
		s.expectedFeatures = comp.Features
	}

	if !gproto.Equal(s.expectedComponent, comp.Component) {
		changed = true
		s.expectedComponentIdx++
		s.expectedComponent = comp.Component
	}

	return changed
}

func (s *ComponentState) syncUnits(comp *component.Component) bool {
	changed := false
	touched := make(map[ComponentUnitKey]bool)
	for _, unit := range comp.Units {
		key := ComponentUnitKey{
			UnitType: unit.Type,
			UnitID:   unit.ID,
		}

		touched[key] = true
		existing, ok := s.Units[key]
		if !ok {
			existing.State = client.UnitStateStarting
			existing.Message = startingMsg
			existing.Payload = nil
			existing.configStateIdx = 0
			existing.unitState = client.UnitStateStarting
			existing.unitMessage = startingMsg
			existing.unitPayload = nil
			changed = true
		}
		existing.err = unit.Err
		if existing.err != nil {
			errMsg := existing.err.Error()
			if existing.State != client.UnitStateFailed || existing.Message != errMsg || diffPayload(existing.Payload, nil) {
				existing.State = client.UnitStateFailed
				existing.Message = existing.err.Error()
				existing.Payload = nil
				changed = true
			}
		}
		s.Units[key] = existing
	}
	for key, unit := range s.Units {
		_, ok := touched[key]
		if !ok {
			if unit.State != client.UnitStateStopped {
				unit.State = client.UnitStateStopped
				unit.Message = stoppedMsg
				unit.Payload = nil
				unit.unitState = client.UnitStateStopped
				unit.unitMessage = stoppedMsg
				unit.unitPayload = nil
				changed = true

				// unit is a copy and must be set back into the map
				s.Units[key] = unit
			}
		}
	}

	if !gproto.Equal(s.Features, comp.Features) {
		s.Features = comp.Features
		changed = true
	}

	if !gproto.Equal(s.Component, comp.Component) {
		s.Component = comp.Component
		changed = true
	}

	return changed
}

func (s *ComponentState) syncCheckin(checkin *proto.CheckinObserved) bool {
	changed := false
	touched := make(map[ComponentUnitKey]bool)
	for _, unit := range checkin.Units {
		key := ComponentUnitKey{
			UnitType: client.UnitType(unit.Type),
			UnitID:   unit.Id,
		}

		var payload map[string]interface{}
		if unit.Payload != nil {
			payload = unit.Payload.AsMap()
		}
		touched[key] = true
		_, inExpected := s.expectedUnits[key]
		existing := s.Units[key]
		existing.unitState = client.UnitState(unit.State)
		existing.unitMessage = unit.Message
		existing.unitPayload = payload
		existing.configStateIdx = unit.ConfigStateIdx
		if existing.err != nil && existing.unitState != client.UnitStateStopped {
			errMsg := existing.err.Error()
			if existing.State != client.UnitStateFailed || existing.Message != errMsg || diffPayload(existing.Payload, nil) {
				changed = true
				existing.State = client.UnitStateFailed
				existing.Message = errMsg
				existing.Payload = nil
			}
		} else if !inExpected && existing.unitState != client.UnitStateStopped {
			if existing.State != client.UnitStateFailed || existing.Message != unknownMsg || diffPayload(existing.Payload, nil) {
				changed = true
				existing.State = client.UnitStateFailed
				existing.Message = unknownMsg
				existing.Payload = nil
			}
		} else {
			if existing.unitState != existing.State || existing.unitMessage != existing.Message || diffPayload(existing.unitPayload, existing.Payload) {
				changed = true
				existing.State = existing.unitState
				existing.Message = existing.unitMessage
				existing.Payload = existing.unitPayload
			}
		}
		s.Units[key] = existing
	}

	for key, unit := range s.Units {
		_, ok := touched[key]
		if !ok {
			unit.unitState = client.UnitStateStarting
			unit.unitMessage = ""
			unit.unitPayload = nil
			unit.configStateIdx = 0
			if unit.err != nil {
				errMsg := unit.err.Error()
				if unit.State != client.UnitStateFailed || unit.Message != errMsg || diffPayload(unit.Payload, nil) {
					changed = true
					unit.State = client.UnitStateFailed
					unit.Message = errMsg
					unit.Payload = nil
				}
			} else if unit.State != client.UnitStateStarting && unit.State != client.UnitStateStopped {
				if unit.State != client.UnitStateFailed || unit.Message != missingMsg || diffPayload(unit.Payload, nil) {
					changed = true
					unit.State = client.UnitStateFailed
					unit.Message = missingMsg
					unit.Payload = nil
				}
			}
		}

		s.Units[key] = unit
	}

	if checkin.VersionInfo != nil {
		if checkin.VersionInfo.Name != "" && s.VersionInfo.Name != checkin.VersionInfo.Name {
			s.VersionInfo.Name = checkin.VersionInfo.Name
			changed = true
		}
		if checkin.VersionInfo.Version != "" && s.VersionInfo.Version != checkin.VersionInfo.Version {
			s.VersionInfo.Version = checkin.VersionInfo.Version
			changed = true
		}
		if checkin.VersionInfo.Meta != nil && diffMeta(s.VersionInfo.Meta, checkin.VersionInfo.Meta) {
			s.VersionInfo.Meta = checkin.VersionInfo.Meta
			changed = true
		}
	}

	if s.FeaturesIdx != checkin.FeaturesIdx {
		s.FeaturesIdx = checkin.FeaturesIdx
		if checkin.Features != nil {
			s.Features = &proto.Features{
				Fqdn: &proto.FQDNFeature{
					Enabled: checkin.Features.Fqdn.Enabled,
				},
			}
		}
		changed = true
	}

	if s.ComponentIdx != checkin.ComponentIdx {
		s.ComponentIdx = checkin.ComponentIdx
		changed = true
	}

	return changed
}

func (s *ComponentState) unsettled() bool {
	if len(s.expectedUnits) != len(s.Units) {
		// mismatch on unit count
		return true
	}

	for ek, e := range s.expectedUnits {
		o, ok := s.Units[ek]
		if !ok {
			// unit missing
			return true
		}
		if o.configStateIdx != e.configStateIdx ||
			e.state != o.State {
			// config or state mismatch
			return true
		}
	}

	return s.FeaturesIdx != s.expectedFeaturesIdx || s.ComponentIdx != s.expectedComponentIdx
}

func (s *ComponentState) toCheckinExpected() *proto.CheckinExpected {
	units := make([]*proto.UnitExpected, 0, len(s.expectedUnits))

	for k, u := range s.expectedUnits {
		e := &proto.UnitExpected{
			Id:             k.UnitID,
			Type:           proto.UnitType(k.UnitType),
			State:          proto.State(u.state),
			LogLevel:       proto.UnitLogLevel(u.logLevel),
			ConfigStateIdx: u.configStateIdx,
			Config:         nil,
		}
		o, ok := s.Units[k]
		if !ok || o.configStateIdx != u.configStateIdx {
			e.Config = u.config
		}
		if u.err != nil {
			if !ok || o.unitState == client.UnitStateStopped || o.configStateIdx == 0 {
				// unit not existing, already stopped or never sent
				continue
			}
			// unit in error needs to be stopped (no config change)
			e.State = proto.State_STOPPED
			e.ConfigStateIdx = o.configStateIdx
			e.Config = nil
		}
		units = append(units, e)
	}

	return &proto.CheckinExpected{
		Units:        units,
		Features:     s.expectedFeatures,
		FeaturesIdx:  s.expectedFeaturesIdx,
		Component:    s.expectedComponent,
		ComponentIdx: s.expectedComponentIdx,
	}
}

func (s *ComponentState) cleanupStopped() bool {
	cleaned := false
	for ek, e := range s.expectedUnits {
		if e.state == client.UnitStateStopped {
			// should be stopped; check if observed is also reporting stopped
			o, ok := s.Units[ek]
			if ok && o.unitState == client.UnitStateStopped {
				// its also stopped; so it can now be removed from both
				delete(s.expectedUnits, ek)
				delete(s.Units, ek)
				cleaned = true
			}
		}
	}
	for k, u := range s.Units {
		_, ok := s.expectedUnits[k]
		if !ok && u.State == client.UnitStateStopped {
			// stopped unit that is not expected (remove it)
			delete(s.Units, k)
			cleaned = true
		}
	}
	return cleaned
}

// forceState force updates the state for the entire component, forcing that state on all units.
func (s *ComponentState) forceState(state client.UnitState, msg string) bool {
	changed := false
	if s.State != state || s.Message != msg {
		s.State = state
		s.Message = msg
		changed = true
	}
	for k, unit := range s.Units {
		unitState := state
		unitMsg := msg
		if unit.err != nil && state != client.UnitStateStopped {
			// must stay as failed as then unit config is in error
			unitState = client.UnitStateFailed
			unitMsg = unit.err.Error()
		}
		if unit.State != unitState || unit.Message != unitMsg || diffPayload(unit.Payload, nil) {
			unit.State = unitState
			unit.Message = unitMsg
			unit.Payload = nil
			changed = true
		}

		// unit is a copy and must be set back into the map
		s.Units[k] = unit
	}
	return changed
}

// forceExpectedState force updates the expected state for the entire component, forcing that state on all expected units.
func (s *ComponentState) forceExpectedState(state client.UnitState) {
	for k, unit := range s.expectedUnits {
		if unit.state != state {
			unit.state = state
		}

		// unit is a copy and must be set back into the map
		s.expectedUnits[k] = unit
	}
}

// compState updates just the component state not all the units.
func (s *ComponentState) compState(state client.UnitState, msg string) bool {
	if s.State != state || s.Message != msg {
		s.State = state
		s.Message = msg
		return true
	}
	return false
}

func diffPayload(existing map[string]interface{}, new map[string]interface{}) bool {
	if existing == nil && new != nil {
		return true
	}
	if existing != nil && new == nil {
		return true
	}
	return !reflect.DeepEqual(existing, new)
}

func diffMeta(existing map[string]string, new map[string]string) bool {
	if existing == nil && new != nil {
		return true
	}
	if existing != nil && new == nil {
		return true
	}
	return !reflect.DeepEqual(existing, new)
}
