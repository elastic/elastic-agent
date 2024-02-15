// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package store

import (
	"errors"
	"fmt"
	"io"

	"gopkg.in/yaml.v2"

	"github.com/elastic/elastic-agent/internal/pkg/fleetapi"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

// actionStore receives multiples actions to persist to disk, the implementation of the store only
// take care of action policy change every other action are discarded. The store will only keep the
// last good action on disk, we assume that the action is added to the store after it was ACK with
// Fleet. The store is not threadsafe.
// The actionStore is deprecated, please use and extend the stateStore instead. The actionStore will be eventually removed.
// Deprecated.
type actionStore struct {
	log    *logger.Logger
	store  storeLoad
	dirty  bool
	action action
}

// newActionStore creates a new action store.
func newActionStore(log *logger.Logger, store storeLoad) (*actionStore, error) {
	// If the store exists we will read it, if an error is returned we log it
	// and return an empty store.
	reader, err := store.Load()
	if err != nil {
		log.Warnf("failed to load action store, returning empty contents: %v", err.Error())
		return &actionStore{log: log, store: store}, nil
	}
	defer reader.Close()

	var action actionPolicyChangeSerializer

	dec := yaml.NewDecoder(reader)
	err = dec.Decode(&action)
	if errors.Is(err, io.EOF) {
		return &actionStore{
			log:   log,
			store: store,
		}, nil
	}
	if err != nil {
		return nil, err
	}

	apc := fleetapi.ActionPolicyChange(action)

	return &actionStore{
		log:    log,
		store:  store,
		action: &apc,
	}, nil
}

// add is only taking care of ActionPolicyChange for now and will only keep the last one it receive,
// any other type of action will be silently ignored.
func (s *actionStore) add(a action) {
	switch v := a.(type) {
	case *fleetapi.ActionPolicyChange, *fleetapi.ActionUnenroll:
		// Only persist the action if the action is different.
		if s.action != nil && s.action.ID() == v.ID() {
			return
		}
		s.dirty = true
		s.action = a
	}
}

// save saves actions to backing store.
func (s *actionStore) save() error {
	defer func() { s.dirty = false }()
	if !s.dirty {
		return nil
	}

	var reader io.Reader
	if apc, ok := s.action.(*fleetapi.ActionPolicyChange); ok {
		serialize := actionPolicyChangeSerializer(*apc)

		r, err := jsonToReader(&serialize)
		if err != nil {
			return err
		}

		reader = r
	} else if aun, ok := s.action.(*fleetapi.ActionUnenroll); ok {
		serialize := actionUnenrollSerializer(*aun)

		r, err := jsonToReader(&serialize)
		if err != nil {
			return err
		}

		reader = r
	}

	if reader == nil {
		return fmt.Errorf("incompatible type, expected ActionPolicyChange and received %T", s.action)
	}

	if err := s.store.Save(reader); err != nil {
		return err
	}
	s.log.Debugf("save on disk action policy change: %+v", s.action)
	return nil
}

// actions returns a slice of action to execute in order, currently only a action policy change is
// persisted.
func (s *actionStore) actions() []action {
	if s.action == nil {
		return []action{}
	}

	return []action{s.action}
}

// actionPolicyChangeSerializer is a struct that adds a YAML serialization, I don't think serialization
// is a concern of the fleetapi package. I went this route so I don't have to do much refactoring.
//
// There are four ways to achieve the same results:
// 1. We create a second struct that map the existing field.
// 2. We add the serialization in the fleetapi.
// 3. We move the actual action type outside the actual fleetapi package.
// 4. We have two sets of type.
//
// This could be done in a refactoring.
type actionPolicyChangeSerializer struct {
	ActionID   string                          `json:"id" yaml:"id"`
	ActionType string                          `json:"type" yaml:"type"`
	Data       fleetapi.ActionPolicyChangeData `json:"data,omitempty" yaml:"data,omitempty"`
}

// add a guards between the serializer structs and the original struct.
var _ = actionPolicyChangeSerializer(fleetapi.ActionPolicyChange{})

// actionUnenrollSerializer is a struct that adds a YAML serialization,
type actionUnenrollSerializer struct {
	ActionID   string           `json:"action_id"`
	ActionType string           `json:"action_type"`
	IsDetected bool             `json:"is_detected"`
	Signed     *fleetapi.Signed `json:"signed,omitempty"`
}

// add a guards between the serializer structs and the original struct.
var _ = actionUnenrollSerializer(fleetapi.ActionUnenroll{})
