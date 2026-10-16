// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package workflowrunner

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	storeFileName = "workflow_runner_completed.json"
	// storeRetention bounds how long a completed action is remembered. Fleet
	// stops redelivering an action once it has expired, and Kibana sets short
	// expirations for workflow steps.
	storeRetention = 24 * time.Hour
)

type storeEntry struct {
	CompletedAt time.Time              `json:"completed_at"`
	Ack         map[string]interface{} `json:"ack"`
}

// Store remembers the ack returned for each completed action so a redelivered
// action returns the original result instead of repeating the HTTP call.
// It never contains request headers or bodies.
type Store struct {
	mu      sync.Mutex
	path    string
	now     func() time.Time
	entries map[string]storeEntry
}

// OpenStore loads the store from dir, creating an empty one when the file does not exist.
func OpenStore(dir string) (*Store, error) {
	s := &Store{
		path:    filepath.Join(dir, storeFileName),
		now:     time.Now,
		entries: map[string]storeEntry{},
	}
	data, err := os.ReadFile(s.path)
	if errors.Is(err, fs.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", s.path, err)
	}
	if err := json.Unmarshal(data, &s.entries); err != nil {
		// A corrupt file must not stop the runner; start empty.
		s.entries = map[string]storeEntry{}
	}
	s.pruneLocked()
	return s, nil
}

// Get returns the ack stored for actionID, if any.
func (s *Store) Get(actionID string) (map[string]interface{}, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.entries[actionID]
	if !ok || s.now().Sub(e.CompletedAt) > storeRetention {
		return nil, false
	}
	return e.Ack, true
}

// Put records the ack for actionID and persists the store.
func (s *Store) Put(actionID string, ack map[string]interface{}) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries[actionID] = storeEntry{CompletedAt: s.now(), Ack: ack}
	s.pruneLocked()
	return s.saveLocked()
}

func (s *Store) pruneLocked() {
	now := s.now()
	for id, e := range s.entries {
		if now.Sub(e.CompletedAt) > storeRetention {
			delete(s.entries, id)
		}
	}
}

func (s *Store) saveLocked() error {
	data, err := json.Marshal(s.entries)
	if err != nil {
		return fmt.Errorf("encoding completed actions: %w", err)
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("writing %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, s.path); err != nil {
		return fmt.Errorf("replacing %s: %w", s.path, err)
	}
	return nil
}
