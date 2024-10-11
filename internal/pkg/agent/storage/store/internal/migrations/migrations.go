// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package migrations

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"time"

	"gopkg.in/yaml.v2"
)

type StateStore struct {
	Action      Action        `yaml:"action"`
	AckToken    string        `yaml:"ack_token"`
	ActionQueue []ActionQueue `yaml:"action_queue"`
}

// Action is a struct to read an Action Policy Change from its old
// YAML format.
type Action struct {
	ActionID     string                 `yaml:"action_id"`
	Type         string                 `yaml:"action_type"`
	StartTime    time.Time              `yaml:"start_time,omitempty"`
	SourceURI    string                 `yaml:"source_uri,omitempty"`
	RetryAttempt int                    `yaml:"retry_attempt,omitempty"`
	Policy       map[string]interface{} `yaml:"policy,omitempty"`
	IsDetected   bool                   `yaml:"is_detected,omitempty"`
}

// ActionQueue is a struct to read the action queue from its old YAML format.
type ActionQueue struct {
	ActionID       string                 `yaml:"action_id"`
	Type           string                 `yaml:"type"`
	StartTime      time.Time              `yaml:"start_time,omitempty"`
	ExpirationTime time.Time              `yaml:"expiration,omitempty"`
	Version        string                 `yaml:"version,omitempty"`
	SourceURI      string                 `yaml:"source_uri,omitempty"`
	RetryAttempt   int                    `yaml:"retry_attempt,omitempty"`
	Policy         map[string]interface{} `yaml:"policy,omitempty"`
	IsDetected     bool                   `yaml:"is_detected,omitempty"`
}

type loader interface {
	Load() (io.ReadCloser, error)
}

// LoadActionStore loads an action store from loader.
func LoadActionStore(loader loader) (*Action, error) {
	return LoadStore[Action](loader)
}

// LoadYAMLStateStore loads the old YAML state store from loader.
func LoadYAMLStateStore(loader loader) (*StateStore, error) {
	return LoadStore[StateStore](loader)
}

// LoadStore loads a YAML file.
func LoadStore[Store any](loader loader) (store *Store, err error) {
	// Store is a generic type, this might be needed.
	store = new(Store)

	reader, err := loader.Load()
	if err != nil {
		return nil, fmt.Errorf("failed to load action store: %w", err)
	}
	defer func() {
		errClose := reader.Close()
		if errClose != nil {
			errClose = fmt.Errorf(
				"migration storeLoad failed to close reader: %w", errClose)
		}
		err = errors.Join(err, errClose)
	}()

	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}
	buff := bytes.NewReader(data)

	dec := yaml.NewDecoder(buff)
	err = dec.Decode(&store)
	if errors.Is(err, io.EOF) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("could not YAML unmarshal action from action store: %w", err)
	}

	return store, nil
}
