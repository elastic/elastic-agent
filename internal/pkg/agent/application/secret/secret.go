// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

// Package secret manages application secrets.
package secret

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/elastic/elastic-agent/internal/pkg/agent/vault"
	"github.com/elastic/elastic-agent/internal/pkg/agent/vault/aesgcm"
)

const AgentSecretKey = "secret"

// mutex for secret create calls
var mxCreate sync.Mutex

// Secret is the structure that is JSON serialized and stored
type Secret struct {
	Value     []byte    `json:"v"` // binary value
	CreatedOn time.Time `json:"t"` // date/time the secret was created on
}

// CreateAgentSecret creates agent secret key if it doesn't exist
func CreateAgentSecret(ctx context.Context, opts ...vault.OptionFunc) error {
	return Create(ctx, AgentSecretKey, opts...)
}

// Create creates secret and stores it in the vault under given key
func Create(ctx context.Context, key string, opts ...vault.OptionFunc) error {
	v, err := vault.New(ctx, opts...)
	if err != nil {
		return fmt.Errorf("could not create new vault: %w", err)
	}
	defer v.Close()

	// Thread-safe key creation
	mxCreate.Lock()
	defer mxCreate.Unlock()

	// Check if the key exists
	exists, err := v.Exists(ctx, key)
	if err != nil {
		return err
	}
	if exists {
		return nil
	}

	// Create new AES256 key
	k, err := aesgcm.NewKey(aesgcm.AES256)
	if err != nil {
		return err
	}

	secret := Secret{
		Value:     k,
		CreatedOn: time.Now().UTC(),
	}

	return set(ctx, v, key, secret)
}

// GetAgentSecret read the agent secret from the vault
func GetAgentSecret(ctx context.Context, opts ...vault.OptionFunc) (secret Secret, err error) {
	return Get(ctx, AgentSecretKey, opts...)
}

// SetAgentSecret saves the agent secret from the vault
// This is needed for migration from 8.3.0-8.3.2 to higher versions
func SetAgentSecret(ctx context.Context, secret Secret, opts ...vault.OptionFunc) error {
	return Set(ctx, AgentSecretKey, secret, opts...)
}

// Get reads the secret key from the vault
func Get(ctx context.Context, key string, opts ...vault.OptionFunc) (secret Secret, err error) {
	// open vault readonly, will not create the vault directory or the seed it was not created before
	opts = append(opts, vault.WithReadonly(true))
	v, err := vault.New(ctx, opts...)
	if err != nil {
		return secret, err
	}
	defer v.Close()

	b, err := v.Get(ctx, key)
	if err != nil {
		return secret, err
	}

	err = json.Unmarshal(b, &secret)
	return secret, err
}

// Set saves the secret key to the vault
func Set(ctx context.Context, key string, secret Secret, opts ...vault.OptionFunc) error {
	v, err := vault.New(ctx, opts...)
	if err != nil {
		return fmt.Errorf("could not create new vault: %w", err)
	}
	defer v.Close()
	return set(ctx, v, key, secret)
}

func set(ctx context.Context, v vault.Vault, key string, secret Secret) error {
	b, err := json.Marshal(secret)
	if err != nil {
		return fmt.Errorf("could not marshal secret: %w", err)
	}

	return v.Set(ctx, key, b)
}

// Remove removes the secret key from the vault
func Remove(ctx context.Context, key string, opts ...vault.OptionFunc) error {
	v, err := vault.New(ctx, opts...)
	if err != nil {
		return fmt.Errorf("could not create new vault: %w", err)
	}
	defer v.Close()

	return v.Remove(ctx, key)
}
