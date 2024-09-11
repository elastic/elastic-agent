// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build !darwin

package vault

import (
	"context"
	"errors"
)

var ErrImplementationNotAvailable = errors.New("vault keychain implementation is not available")

// Empty DarwinKeyChainVault implementation for non-darwin OSes
type DarwinKeyChainVault struct {
}

func (d DarwinKeyChainVault) Exists(ctx context.Context, key string) (bool, error) {
	return false, ErrImplementationNotAvailable
}

func (d DarwinKeyChainVault) Get(ctx context.Context, key string) (dec []byte, err error) {
	return nil, ErrImplementationNotAvailable
}

func (d DarwinKeyChainVault) Set(ctx context.Context, key string, data []byte) (err error) {
	return ErrImplementationNotAvailable
}

func (d DarwinKeyChainVault) Remove(ctx context.Context, key string) (err error) {
	return ErrImplementationNotAvailable
}

func (d DarwinKeyChainVault) Close() error {
	return ErrImplementationNotAvailable
}

func NewDarwinKeyChainVault(ctx context.Context, opts Options) (v *DarwinKeyChainVault, err error) {
	return nil, ErrImplementationNotAvailable
}
