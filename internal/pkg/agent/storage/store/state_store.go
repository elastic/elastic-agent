// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/elastic/elastic-agent/internal/pkg/agent/storage"
	"github.com/elastic/elastic-agent/internal/pkg/conv"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi/acker"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

type store interface {
	Save(io.Reader) error
}

type storeLoad interface {
	store
	Load() (io.ReadCloser, error)
}

type action = fleetapi.Action

// StateStore is a combined agent state storage initially derived from the former actionStore
// and modified to allow persistence of additional agent specific state information.
// The following is the original actionStore implementation description:
// receives multiples actions to persist to disk, the implementation of the store only
// take care of action policy change every other action are discarded. The store will only keep the
// last good action on disk, we assume that the action is added to the store after it was ACK with
// Fleet. The store is not thread safe.
type StateStore struct {
	log   *logger.Logger
	store storeLoad
	dirty bool
	state state

	mx sync.RWMutex
}

type state struct {
	action   action
	ackToken string
	// TODO: the queue is for scheduled actions. Set its type accordingly.
	queue []action
}

// actionSerializer is a combined yml serializer for the ActionPolicyChange and ActionUnenroll
// it is used to read the yaml file and assign the action to state.action as we must provide the
// underlying struct that provides the action interface.
// TODO: get rid of this type
type actionSerializer struct {
	ID         string               `json:"action_id"`
	Type       string               `json:"action_type"`
	Data       actionDataSerializer `json:"data,omitempty"`
	IsDetected *bool                `json:"is_detected,omitempty"`
	Signed     *fleetapi.Signed     `json:"signed,omitempty"`
}

type actionDataSerializer struct {
	Policy map[string]interface{} `json:"policy" yaml:"policy,omitempty"`
}

// stateSerializer is used to serialize the state to yaml.
// action serialization is handled through the actionSerializer struct
// queue serialization is handled through yaml struct tags or the actions unmarshaller defined in fleetapi
// TODO clean up action serialization (have it be part of the fleetapi?)
type stateSerializer struct {
	Action   *actionSerializer `json:"action,omitempty"`
	AckToken string            `json:"ack_token,omitempty"`
	Queue    fleetapi.Actions  `json:"action_queue,omitempty"`
}

// NewStateStoreWithMigration creates a new state store and migrates the old one.
func NewStateStoreWithMigration(ctx context.Context, log *logger.Logger, actionStorePath, stateStorePath string) (*StateStore, error) {

	stateDiskStore := storage.NewEncryptedDiskStore(ctx, stateStorePath)
	err := migrateStateStore(log, actionStorePath, stateDiskStore)
	if err != nil {
		return nil, err
	}

	return NewStateStore(log, storage.NewEncryptedDiskStore(ctx, stateStorePath))
}

// NewStateStoreActionAcker creates a new state store backed action acker.
func NewStateStoreActionAcker(acker acker.Acker, store *StateStore) *StateStoreActionAcker {
	return &StateStoreActionAcker{acker: acker, store: store}
}

// NewStateStore creates a new state store.
func NewStateStore(log *logger.Logger, store storeLoad) (*StateStore, error) {
	// If the store exists we will read it, if an error is returned we log it
	// and return an empty store.
	reader, err := store.Load()
	if err != nil {
		log.Warnf("failed to load state store, returning empty contents: %v", err.Error())
		return &StateStore{log: log, store: store}, nil
	}
	defer reader.Close()

	var serializer stateSerializer

	dec := json.NewDecoder(reader)
	err = dec.Decode(&serializer)
	if errors.Is(err, io.EOF) {
		return &StateStore{
			log:   log,
			store: store,
		}, nil
	}

	if err != nil {
		return nil, err
	}

	st := state{
		ackToken: serializer.AckToken,
		queue:    serializer.Queue,
	}

	if serializer.Action != nil {
		// TODO: use ActionType instead
		if serializer.Action.IsDetected != nil {
			st.action = &fleetapi.ActionUnenroll{
				ActionID:   serializer.Action.ID,
				ActionType: serializer.Action.Type,
				IsDetected: *serializer.Action.IsDetected,
				Signed:     serializer.Action.Signed,
			}
		} else {
			st.action = &fleetapi.ActionPolicyChange{
				ActionID:   serializer.Action.ID,
				ActionType: serializer.Action.Type,
				Data: fleetapi.ActionPolicyChangeData{
					// Fix Policy, in order to make it consistent with the policy
					// received from the fleet gateway as nested map[string]interface{}
					Policy: conv.YAMLMapToJSONMap(serializer.Action.Data.Policy),
				},
			}
		}
	}

	return &StateStore{
		log:   log,
		store: store,
		state: st,
	}, nil
}

func migrateStateStore(
	log *logger.Logger,
	actionStorePath string,
	stateDiskStore storage.Storage) (err error) {

	log = log.Named("state_migration")
	actionDiskStore := storage.NewDiskStore(actionStorePath)

	stateStoreExits, err := stateDiskStore.Exists()
	if err != nil {
		log.Errorf("failed to check if state store exists: %v", err)
		return err
	}

	// do not migrate if the state store already exists
	if stateStoreExits {
		log.Debugf("state store already exists")
		return nil
	}

	actionStoreExits, err := actionDiskStore.Exists()
	if err != nil {
		log.Errorf("failed to check if action store %s exists: %v", actionStorePath, err)
		return err
	}

	// delete the actions store file upon successful migration
	defer func() {
		if err == nil && actionStoreExits {
			err = actionDiskStore.Delete()
			if err != nil {
				log.Errorf("failed to delete action store %s exists: %v", actionStorePath, err)
			}
		}
	}()

	// nothing to migrate if the action store doesn't exists
	if !actionStoreExits {
		log.Debugf("action store %s doesn't exists, nothing to migrate", actionStorePath)
		return nil
	}

	actionStore, err := newActionStore(log, actionDiskStore)
	if err != nil {
		log.Errorf("failed to create action store %s: %v", actionStorePath, err)
		return err
	}

	// no actions stored nothing to migrate
	if len(actionStore.actions()) == 0 {
		log.Debugf("no actions stored in the action store %s, nothing to migrate", actionStorePath)
		return nil
	}

	stateStore, err := NewStateStore(log, stateDiskStore)
	if err != nil {
		return err
	}

	// set actions from the action store to the state store
	stateStore.Add(actionStore.actions()[0])

	err = stateStore.Save()
	if err != nil {
		log.Debugf("failed to save agent state store, err: %v", err)
	}
	return err
}

// Add is only taking care of ActionPolicyChange for now and will only keep the last one it receive,
// any other type of action will be silently ignored.
// TODO: fix docs: state:
//   - the valid actions,
//   - it silently discard invalid actions
//   - perhaps rename it as it does not add to the queue, but sets the current
//     action
func (s *StateStore) Add(a action) {
	s.mx.Lock()
	defer s.mx.Unlock()

	switch v := a.(type) {
	case *fleetapi.ActionPolicyChange, *fleetapi.ActionUnenroll:
		// Only persist the action if the action is different.
		if s.state.action != nil && s.state.action.ID() == v.ID() {
			return
		}
		s.dirty = true
		s.state.action = a
	}
}

// SetAckToken set ack token to the agent state
func (s *StateStore) SetAckToken(ackToken string) {
	s.mx.Lock()
	defer s.mx.Unlock()

	if s.state.ackToken == ackToken {
		return
	}
	s.dirty = true
	s.state.ackToken = ackToken
}

// SetQueue sets the action_queue to agent state
func (s *StateStore) SetQueue(q []action) {
	s.mx.Lock()
	defer s.mx.Unlock()
	s.state.queue = q
	s.dirty = true

}

// Save saves the actions into a state store.
func (s *StateStore) Save() error {
	s.mx.Lock()
	defer s.mx.Unlock()

	defer func() { s.dirty = false }()
	if !s.dirty {
		return nil
	}

	var reader io.Reader
	serialize := stateSerializer{
		AckToken: s.state.ackToken,
		Queue:    s.state.queue,
	}

	if s.state.action != nil {
		switch a := s.state.action.(type) {
		case *fleetapi.ActionPolicyChange:
			serialize.Action = &actionSerializer{
				ID:   a.ActionID,
				Type: a.ActionType,
				Data: actionDataSerializer{
					Policy: a.Data.Policy,
				}}
		case *fleetapi.ActionUnenroll:
			serialize.Action = &actionSerializer{
				ID:         a.ActionID,
				Type:       a.ActionType,
				IsDetected: &a.IsDetected,
				Signed:     a.Signed,
			}
		default:
			return fmt.Errorf("incompatible type, expected ActionPolicyChange "+
				"or ActionUnenroll but received %T", s.state.action)
		}
	}

	reader, err := jsonToReader(&serialize)
	if err != nil {
		return err
	}

	if err := s.store.Save(reader); err != nil {
		return err
	}
	s.log.Debugf("save state on disk : %+v", s.state)
	return nil
}

// Queue returns a copy of the queue
func (s *StateStore) Queue() []action {
	s.mx.RLock()
	defer s.mx.RUnlock()
	q := make([]action, len(s.state.queue))
	copy(q, s.state.queue)
	return q
}

// Actions returns a slice of action to execute in order, currently only a action policy change is
// persisted.
func (s *StateStore) Actions() []action {
	s.mx.RLock()
	defer s.mx.RUnlock()

	if s.state.action == nil {
		return []action{}
	}

	return []action{s.state.action}
}

// AckToken return the agent state persisted ack_token
func (s *StateStore) AckToken() string {
	s.mx.RLock()
	defer s.mx.RUnlock()
	return s.state.ackToken
}

// StateStoreActionAcker wraps an existing acker and will send any acked event to the action store,
// its up to the action store to decide if we need to persist the event for future replay or just
// discard the event.
type StateStoreActionAcker struct {
	acker acker.Acker
	store *StateStore
}

// Ack acks action using underlying acker.
// After action is acked it is stored to backing store.
func (a *StateStoreActionAcker) Ack(ctx context.Context, action fleetapi.Action) error {
	if err := a.acker.Ack(ctx, action); err != nil {
		return err
	}
	a.store.Add(action)
	return a.store.Save()
}

// Commit commits acks.
func (a *StateStoreActionAcker) Commit(ctx context.Context) error {
	return a.acker.Commit(ctx)
}

func jsonToReader(in interface{}) (io.Reader, error) {
	data, err := json.Marshal(in)
	if err != nil {
		return nil, fmt.Errorf("could not marshal to YAML: %w", err)
	}
	return bytes.NewReader(data), nil
}
