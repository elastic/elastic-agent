// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build !darwin

package vault

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestDarwinKeyChainVault_Close(t *testing.T) {
	dkcv := new(DarwinKeyChainVault)
	err := dkcv.Close()
	assert.ErrorIs(t, err, ErrImplementationNotAvailable, "when not running in darwin we cannot call any function on a keychain vault, the returned error should be ErrImplementationNotAvailable")
}

func TestDarwinKeyChainVault_Exists(t *testing.T) {
	dkcv := new(DarwinKeyChainVault)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	exists, err := dkcv.Exists(ctx, "key")
	assert.False(t, exists, "when not running in darwin we cannot call any function on a keychain vault, the returned value should be the zero value")
	assert.ErrorIs(t, err, ErrImplementationNotAvailable, "when not running in darwin we cannot call any function on a keychain vault, the returned error should be ErrImplementationNotAvailable")
}

func TestDarwinKeyChainVault_Get(t *testing.T) {
	dkcv := new(DarwinKeyChainVault)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	keyBytes, err := dkcv.Get(ctx, "key")
	assert.Nil(t, keyBytes, "when not running in darwin we cannot call any function on a keychain vault, the returned value should be the zero value")
	assert.ErrorIs(t, err, ErrImplementationNotAvailable, "when not running in darwin we cannot call any function on a keychain vault, the returned error should be ErrImplementationNotAvailable")
}

func TestDarwinKeyChainVault_Remove(t *testing.T) {
	dkcv := new(DarwinKeyChainVault)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := dkcv.Remove(ctx, "key")
	assert.ErrorIs(t, err, ErrImplementationNotAvailable, "when not running in darwin we cannot call any function on a keychain vault, the returned error should be ErrImplementationNotAvailable")
}

func TestDarwinKeyChainVault_Set(t *testing.T) {
	dkcv := new(DarwinKeyChainVault)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := dkcv.Set(ctx, "key", []byte("data"))
	assert.ErrorIs(t, err, ErrImplementationNotAvailable, "when not running in darwin we cannot call any function on a keychain vault, the returned error should be ErrImplementationNotAvailable")
}

func TestNewDarwinKeyChainVault(t *testing.T) {
	v, err := NewDarwinKeyChainVault(context.TODO(), Options{})
	assert.Nil(t, v, "when not running in darwin we cannot instantiate a keychain vault")
	assert.ErrorIs(t, err, ErrImplementationNotAvailable, "when not running in darwin we cannot call any function on a keychain vault, the returned error should be ErrImplementationNotAvailable")
}
