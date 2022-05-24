// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package secret

import (
	"encoding/json"
	"runtime"
	"time"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/vault"
)

const agentSecretKey = "secret"

// Secret is the structure that is JSON serialized and stored
type Secret struct {
	Value     []byte    `json:"v"` // binary value
	CreatedOn time.Time `json:"t"` // date/time the secret was created on
}

type options struct {
	vaultPath string
}

type OptionFunc func(o *options)

// WithVaultPath allows to specify the vault path, doesn't apply for darwin
func WithVaultPath(vaultPath string) OptionFunc {
	return func(o *options) {
		if runtime.GOOS == "darwin" {
			return
		}
		o.vaultPath = vaultPath
	}
}

// CreateAgentSecret creates agent secret key if it doesn't exist
func CreateAgentSecret(opts ...OptionFunc) error {
	return Create(agentSecretKey, opts...)
}

// Create creates secret and stores it in the vault under given key
func Create(key string, opts ...OptionFunc) error {
	options := applyOptions(opts...)
	v, err := vault.New(options.vaultPath)
	if err != nil {
		return err
	}
	defer v.Close()

	// Check if the key exists
	exists, err := v.Exists(key)
	if err != nil {
		return err
	}
	if exists {
		return nil
	}

	// Create new AES256 key
	k, err := vault.NewKey(vault.AES256)
	if err != nil {
		return err
	}

	secret := Secret{
		Value:     k,
		CreatedOn: time.Now().UTC(),
	}

	b, err := json.Marshal(secret)
	if err != nil {
		return err
	}

	return v.Set(key, b)
}

// GetAgentSecret read the agent secret from the vault
func GetAgentSecret(opts ...OptionFunc) (secret Secret, err error) {
	return Get(agentSecretKey, opts...)
}

// Get reads the secret key from the vault
func Get(key string, opts ...OptionFunc) (secret Secret, err error) {
	options := applyOptions(opts...)
	v, err := vault.New(options.vaultPath)
	if err != nil {
		return secret, err
	}
	defer v.Close()

	b, err := v.Get(key)
	if err != nil {
		return secret, err
	}

	err = json.Unmarshal(b, &secret)
	return secret, err
}

// Remove removes the secret key from the vault
func Remove(key string, opts ...OptionFunc) error {
	options := applyOptions(opts...)
	v, err := vault.New(options.vaultPath)
	if err != nil {
		return err
	}
	defer v.Close()

	return v.Remove(key)
}

func applyOptions(opts ...OptionFunc) options {
	o := options{
		vaultPath: paths.AgentVaultPath(),
	}

	for _, opt := range opts {
		opt(&o)
	}
	return o
}
