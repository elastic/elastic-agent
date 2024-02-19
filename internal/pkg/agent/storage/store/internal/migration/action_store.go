// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package migration

import (
	"errors"
	"fmt"
	"io"

	"gopkg.in/yaml.v2"
)

// ActionPolicyChange is a struct to read a Action Policy Change from its old
// YAML format.
type ActionPolicyChange struct {
	ActionID   string                 `yaml:"action_id"`
	ActionType string                 `yaml:"action_type"`
	Policy     map[string]interface{} `yaml:"policy,omitempty"`
}

// LoadActionStore loads an action store from .
func LoadActionStore(loader interface{ Load() (io.ReadCloser, error) }) (*ActionPolicyChange, error) {
	reader, err := loader.Load()
	if err != nil {
		return nil, fmt.Errorf("failed to load action store: %w", err)
	}
	defer reader.Close()

	var action ActionPolicyChange

	dec := yaml.NewDecoder(reader)
	err = dec.Decode(&action)
	if errors.Is(err, io.EOF) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("could not YAML unmarshal action from action store: %w", err)
	}

	return &action, nil
}
