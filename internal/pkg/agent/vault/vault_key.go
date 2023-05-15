// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build linux || windows

package vault

import (
	"crypto/sha256"
	"encoding/hex"
)

// fileNameFromKey returns the filename as a hash of the vault seed combined with the key
// this ties the key with the vault seed eliminating the change of attempting
// to decrypt the key for the wrong vault seed value.
func fileNameFromKey(seed []byte, key string) string {
	hash := sha256.Sum256(append(seed, []byte(key)...))
	return hex.EncodeToString(hash[:])
}
