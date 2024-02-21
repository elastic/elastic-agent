// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

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

// LoadActionStore loads an action store from .
func LoadActionStore(loader interface{ Load() (io.ReadCloser, error) }) (*Action, error) {
	return LoadStore[Action](loader)
}

func LoadYAMLStateStore(loader interface{ Load() (io.ReadCloser, error) }) (*StateStore, error) {
	return LoadStore[StateStore](loader)
}

func LoadStore[Store any](loader interface{ Load() (io.ReadCloser, error) }) (store *Store, err error) {
	reader, err := loader.Load()
	if err != nil {
		return nil, fmt.Errorf("failed to load action store: %w", err)
	}
	defer func() {
		err2 := reader.Close()
		if err != nil {
			err = errors.Join(err,
				fmt.Errorf("migration storeLoad failed to close reader: %w", err2))
		}
	}()

	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}
	buff := bytes.NewReader(data)

	dec := yaml.NewDecoder(buff)
	err = dec.Decode(store)
	if errors.Is(err, io.EOF) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("could not YAML unmarshal action from action store: %w", err)
	}

	return store, nil
}
