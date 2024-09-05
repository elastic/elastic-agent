// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package store

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sync"

	"github.com/elastic/elastic-agent/internal/pkg/agent/storage"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi/acker"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

// Version is the current StateStore version. If any breaking change is
// introduced, it should be increased and a migration added.
const Version = "1"

type saver interface {
	Save(io.Reader) error
}

type saveLoader interface {
	saver
	Load() (io.ReadCloser, error)
}

// StateStore stores the agent state:
//   - the last fleet action (not all actions are stored, refer to Save for details)
//   - a queue of scheduled actions
//   - the ack token
//
// See each method documentation for details.
type StateStore struct {
	log   *logger.Logger
	store saveLoader
	dirty bool
	state state

	mx sync.RWMutex
}

type state struct {
	Version          string           `json:"version"`
	ActionSerializer actionSerializer `json:"action,omitempty"`
	AckToken         string           `json:"ack_token,omitempty"`
	Queue            actionQueue      `json:"action_queue,omitempty"`
}

// actionSerializer is JSON Marshaler/Unmarshaler for fleetapi.Action.
type actionSerializer struct {
	json.Marshaler
	json.Unmarshaler

	Action fleetapi.Action
}

// actionQueue stores scheduled actions to be executed and the type is needed
// to make it possible to marshal and unmarshal fleetapi.ScheduledActions.
// The fleetapi package marshal/unmarshal fleetapi.Actions, therefore it does
// not need to handle fleetapi.ScheduledAction separately. However, the store does,
// therefore the need for this type to do so.
type actionQueue []fleetapi.ScheduledAction

// NewStateStoreWithMigration creates a new state store and migrates the old ones.
func NewStateStoreWithMigration(
	ctx context.Context,
	log *logger.Logger,
	actionStorePath,
	stateStorePath string,
	storageOpts ...storage.EncryptedOptionFunc) (*StateStore, error) {
	stateDiskStore, err := storage.NewEncryptedDiskStore(
		ctx, stateStorePath, storageOpts...)
	if err != nil {
		return nil, fmt.Errorf(
			"could not create EncryptedDiskStore when creating StateStoreWithMigration: %w",
			err)
	}

	return newStateStoreWithMigration(log, actionStorePath, stateDiskStore)
}

func newStateStoreWithMigration(
	log *logger.Logger,
	actionStorePath string,
	stateStore storage.Storage) (*StateStore, error) {
	err := migrateActionStoreToStateStore(log, actionStorePath, stateStore)
	if err != nil {
		return nil, fmt.Errorf("failed migrating action store to YAML state store: %w",
			err)
	}

	err = migrateYAMLStateStoreToStateStoreV1(log, stateStore)
	if err != nil {
		return nil, fmt.Errorf("failed migrating YAML store JSON store: %w",
			err)
	}

	return NewStateStore(log, stateStore)
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

	st, err := readState(reader)
	if err != nil {
		return nil, fmt.Errorf("could not parse store content: %w", err)
	}

	if st.Version != Version {
		return nil, fmt.Errorf(
			"invalid state store version, current version is %q loaded store verion is %q",
			Version, st.Version)
	}

	return &StateStore{
		log:   log,
		store: store,
		state: st,
	}, nil
}

// readState parsed the content from reader as JSON to state.
// It's mostly to abstract the parsing of the data so different functions can
// reuse this.
func readState(reader io.ReadCloser) (state, error) {
	st := state{}

	data, err := io.ReadAll(reader)
	if err != nil {
		return state{}, fmt.Errorf("could not read store state: %w", err)
	}

	if len(data) == 0 {
		// empty file
		return state{Version: "1"}, nil
	}

	err = json.Unmarshal(data, &st)
	if err != nil {
		return state{}, fmt.Errorf("could not parse JSON: %w", err)
	}

	return st, nil
}

// SetAction sets the current action. It accepts ActionPolicyChange or
// ActionUnenroll. Any other type will be silently discarded.
func (s *StateStore) SetAction(a fleetapi.Action) {
	s.mx.Lock()
	defer s.mx.Unlock()

	switch v := a.(type) {
	// If any new action type is added, don't forget to update the method's
	// description.
	case *fleetapi.ActionPolicyChange, *fleetapi.ActionUnenroll:
		// Only persist the action if the action is different.
		if s.state.ActionSerializer.Action != nil &&
			s.state.ActionSerializer.Action.ID() == v.ID() {
			return
		}
		s.dirty = true
		s.state.ActionSerializer.Action = a
	default:
		s.log.Debugw("trying to set invalid action type on the state store, ignoring the action",
			"action.type", a.Type(),
			"action.id", a.ID())
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
func (s *StateStore) SetQueue(q []fleetapi.ScheduledAction) {
	s.mx.Lock()
	defer s.mx.Unlock()
	s.state.Queue = q
	s.dirty = true
}

// Save saves the actions into the state store. If the action type is not
// supported or if any error happens, it returns a non-nil error.
func (s *StateStore) Save() (err error) {
	s.mx.Lock()
	defer s.mx.Unlock()

	defer func() {
		if err == nil {
			s.dirty = false
		}
	}()
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

	reader, err = jsonToReader(&s.state)
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
func (s *StateStore) Queue() []fleetapi.ScheduledAction {
	s.mx.RLock()
	defer s.mx.RUnlock()
	q := make([]fleetapi.ScheduledAction, len(s.state.Queue))
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
// After the action is acked it is stored in the StateStore. The StateStore
// decides if the action needs to be persisted or not.
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

func (aq *actionQueue) UnmarshalJSON(data []byte) error {
	actions := fleetapi.Actions{}
	err := json.Unmarshal(data, &actions)
	if err != nil {
		return fmt.Errorf("actionQueue failed to unmarshal: %w", err)
	}

	var scheduledActions []fleetapi.ScheduledAction
	for _, a := range actions {
		sa, ok := a.(fleetapi.ScheduledAction)
		if !ok {
			return fmt.Errorf("actionQueue: action %s isn't a ScheduledAction, "+
				"cannot unmarshal it to actionQueue", a.Type())
		}
		scheduledActions = append(scheduledActions, sa)
	}

	*aq = scheduledActions
	return nil
}

func jsonToReader(in interface{}) (io.Reader, error) {
	data, err := json.Marshal(in)
	if err != nil {
		return nil, fmt.Errorf("could not marshal to JSON: %w", err)
	}
	return bytes.NewReader(data), nil
}
