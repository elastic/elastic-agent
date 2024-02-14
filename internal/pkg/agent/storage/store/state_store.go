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
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi/acker"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

type saver interface {
	Save(io.Reader) error
}

type saveLoader interface {
	saver
	Load() (io.ReadCloser, error)
}

// StateStore is a combined agent state storage initially derived from the former actionStore
// and modified to allow persistence of additional agent specific state information.
// The following is the original actionStore implementation description:
// receives multiples actions to persist to disk, the implementation of the store only
// take care of action policy change every other action are discarded. The store will only keep the
// last good action on disk, we assume that the action is added to the store after it was ACK with
// Fleet. The store is not thread safe.
type StateStore struct {
	log   *logger.Logger
	store saveLoader
	dirty bool
	state state

	mx sync.RWMutex
}

type state struct {
	ActionSerializer actionSerializer `json:"action,omitempty"`
	AckToken         string           `json:"ack_token,omitempty"`
	Queue            fleetapi.Actions `json:"action_queue,omitempty"`
}

func (as *actionSerializer) MarshalJSON() ([]byte, error) {
	return json.Marshal(as.Action)
}

func (as *actionSerializer) UnmarshalJSON(data []byte) error {
	var typeUnmarshaler struct {
		Type string `json:"type,omitempty" yaml:"type,omitempty"`
	}
	err := json.Unmarshal(data, &typeUnmarshaler)
	if err != nil {
		return err
	}

	as.Action = fleetapi.NewAction(typeUnmarshaler.Type)
	err = json.Unmarshal(data, &as.Action)
	if err != nil {
		return err
	}

	return nil
}

// actionSerializer is JSON Marshaler/Unmarshaler for fleetapi.Action.
type actionSerializer struct {
	json.Marshaler
	json.Unmarshaler

	Action fleetapi.Action
}

// NewStateStoreWithMigration creates a new state store and migrates the old one.
func NewStateStoreWithMigration(ctx context.Context, log *logger.Logger, actionStorePath, stateStorePath string) (*StateStore, error) {

	stateDiskStore := storage.NewEncryptedDiskStore(ctx, stateStorePath)
	err := migrateActionStoreToStateStore(log, actionStorePath, stateDiskStore)
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
func NewStateStore(log *logger.Logger, store saveLoader) (*StateStore, error) {
	// If the store exists we will read it, if an error is returned we log it
	// and return an empty store.
	reader, err := store.Load()
	if err != nil {
		log.Warnf("failed to load state store, returning empty contents: %v", err.Error())
		return &StateStore{log: log, store: store}, nil
	}
	defer reader.Close()

	st := state{}

	dec := json.NewDecoder(reader)
	err = dec.Decode(&st)
	if errors.Is(err, io.EOF) {
		return &StateStore{
			log:   log,
			store: store,
		}, nil
	}

	if err != nil {
		return nil, err
	}

	return &StateStore{
		log:   log,
		store: store,
		state: st,
	}, nil
}

func migrateActionStoreToStateStore(
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
	stateStore.SetAction(actionStore.actions()[0])

	err = stateStore.Save()
	if err != nil {
		log.Debugf("failed to save agent state store, err: %v", err)
	}
	return err
}

// SetAction sets the current action. It accepts ActionPolicyChange or
// ActionUnenroll. Any other type will be silently discarded.
func (s *StateStore) SetAction(a fleetapi.Action) {
	s.mx.Lock()
	defer s.mx.Unlock()

	switch v := a.(type) {
	case *fleetapi.ActionPolicyChange, *fleetapi.ActionUnenroll:
		// Only persist the action if the action is different.
		if s.state.ActionSerializer.Action != nil &&
			s.state.ActionSerializer.Action.ID() == v.ID() {
			return
		}
		s.dirty = true
		s.state.ActionSerializer.Action = a
	}
}

// SetAckToken set ack token to the agent state
func (s *StateStore) SetAckToken(ackToken string) {
	s.mx.Lock()
	defer s.mx.Unlock()

	if s.state.AckToken == ackToken {
		return
	}
	s.dirty = true
	s.state.AckToken = ackToken
}

// SetQueue sets the action_queue to agent state
func (s *StateStore) SetQueue(q fleetapi.Actions) {
	s.mx.Lock()
	defer s.mx.Unlock()
	s.state.Queue = q
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

	switch a := s.state.ActionSerializer.Action.(type) {
	case *fleetapi.ActionPolicyChange,
		*fleetapi.ActionUnenroll,
		nil:
		// ok
	default:
		return fmt.Errorf("incompatible type, expected ActionPolicyChange, "+
			"ActionUnenroll or nil, but received %T", a)
	}

	reader, err := jsonToReader(&s.state)
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
func (s *StateStore) Queue() fleetapi.Actions {
	s.mx.RLock()
	defer s.mx.RUnlock()
	q := make([]fleetapi.Action, len(s.state.Queue))
	copy(q, s.state.Queue)
	return q
}

// Action the action to execute. See SetAction for the possible action types.
func (s *StateStore) Action() fleetapi.Action {
	s.mx.RLock()
	defer s.mx.RUnlock()

	if s.state.ActionSerializer.Action == nil {
		return nil
	}

	return s.state.ActionSerializer.Action
}

// AckToken return the agent state persisted ack_token
func (s *StateStore) AckToken() string {
	s.mx.RLock()
	defer s.mx.RUnlock()
	return s.state.AckToken
}

// StateStoreActionAcker wraps an existing acker and will set any acked event
// in the state store. It's up to the state store to decide if we need to
// persist the event for future replay or just discard the event.
type StateStoreActionAcker struct {
	acker acker.Acker
	store *StateStore
}

// Ack acks the action using underlying acker.
// After the action is acked it is stored to backing store.
func (a *StateStoreActionAcker) Ack(ctx context.Context, action fleetapi.Action) error {
	if err := a.acker.Ack(ctx, action); err != nil {
		return err
	}
	a.store.SetAction(action)
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
