// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build darwin

package mage

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAppleKeychainListIdentities(t *testing.T) {
	t.Skip("Flaky test")
	idents, err := _appleKeychain.ListIdentities()
	if err != nil {
		t.Fatal(err)
	}

	assert.NotZero(t, idents)

	for i, ident := range idents {
		t.Log(i, ident)
	}
}

func TestGetAppleSigningInfo(t *testing.T) {
	signingInfo, err := GetAppleSigningInfo()
	if err != nil {
		t.Fatal(err)
	}

	if assert.NotNil(t, signingInfo) {
		assert.False(t, signingInfo.Sign)
	}
}
