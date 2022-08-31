// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

// Package secret manages application secrets.
package secret

import (
	"encoding/json"
	"fmt"
	"runtime"
	"sync"
	"time"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/vault"
)

const agentSecretKey = "secret"

// mutex for secret create calls
var mxCreate sync.Mutex

// Secret is the structure that is JSON serialized and stored
type Secret struct {
	Value     []byte    `json:"v"` // binary value
	CreatedOn time.Time `json:"t"` // date/time the secret was created on
}

type options struct {
	vaultPath string
}

// OptionFunc is the functional configuration type.
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
		return fmt.Errorf("could not create new vault: %w", err)
	}
	defer v.Close()

	// Thread-safe key creation
	mxCreate.Lock()
	defer mxCreate.Unlock()

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

	return set(v, key, secret)
}

// GetAgentSecret read the agent secret from the vault
func GetAgentSecret(opts ...OptionFunc) (secret Secret, err error) {
	return Get(agentSecretKey, opts...)
}

// SetAgentSecret saves the agent secret from the vault
// This is needed for migration from 8.3.0-8.3.2 to higher versions
func SetAgentSecret(secret Secret, opts ...OptionFunc) error {
	return Set(agentSecretKey, secret, opts...)
}

// Get reads the secret key from the vault
func Get(key string, opts ...OptionFunc) (secret Secret, err error) {
	options := applyOptions(opts...)
	// open vault readonly, will not create the vault directory or the seed it was not created before
	v, err := vault.New(options.vaultPath, vault.WithReadonly(true))
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

// Set saves the secret key to the vault
func Set(key string, secret Secret, opts ...OptionFunc) error {
	options := applyOptions(opts...)
	v, err := vault.New(options.vaultPath)
	if err != nil {
		return fmt.Errorf("could not create new vault: %w", err)
	}
	defer v.Close()
	return set(v, key, secret)
}

func set(v *vault.Vault, key string, secret Secret) error {
	b, err := json.Marshal(secret)
	if err != nil {
		return fmt.Errorf("could not marshal secret: %w", err)
	}

	return v.Set(key, b)
}

// Remove removes the secret key from the vault
func Remove(key string, opts ...OptionFunc) error {
	options := applyOptions(opts...)
	v, err := vault.New(options.vaultPath)
	if err != nil {
		return fmt.Errorf("could not create new vault: %w", err)
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
