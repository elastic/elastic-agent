// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build !darwin

package vault

import (
	"context"
	"errors"
)

var ErrorImplementationNotAvailable = errors.New("vault implementation is not available")

// Empty DarwinKeyChainVault implementation for non-darwin OSes
type DarwinKeyChainVault struct {
}

func (d DarwinKeyChainVault) Exists(ctx context.Context, key string) (bool, error) {
	return false, ErrorImplementationNotAvailable
}

func (d DarwinKeyChainVault) Get(ctx context.Context, key string) (dec []byte, err error) {
	return nil, ErrorImplementationNotAvailable
}

func (d DarwinKeyChainVault) Set(ctx context.Context, key string, data []byte) (err error) {
	return ErrorImplementationNotAvailable
}

func (d DarwinKeyChainVault) Remove(ctx context.Context, key string) (err error) {
	return ErrorImplementationNotAvailable
}

func (d DarwinKeyChainVault) Close() error {
	return ErrorImplementationNotAvailable
}

func NewDarwinKeyChainVault(ctx context.Context, name string, opts ...OptionFunc) (v *DarwinKeyChainVault, err error) {
	return nil, ErrorImplementationNotAvailable
}
