// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package crypto

import (
	"bytes"
	"crypto/hmac"
	"errors"
	"fmt"
)

const (
	// https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#pbkdf2
	hashIterations  = 210_000
	hashKeyLength   = 64
	hashSaltLength  = 16
	hashTotalLength = hashSaltLength + hashKeyLength
)

// ErrMismatchedHashAndPassword is the error returned from ComparePBKDF2HashAndPassword when a password and hash do
// not match.
var ErrMismatchedHashAndPassword = errors.New("hashedPassword is not the hash of the given password")

// GeneratePBKDF2FromPassword hashes a password using PBKDF2.
func GeneratePBKDF2FromPassword(password []byte) ([]byte, error) {
	// Generate a random salt
	salt, err := randomBytes(hashSaltLength)
	if err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}

	// Write hash
	// SALT|KEY
	key := stretchPassword(password, salt, hashIterations, hashKeyLength)
	hash := new(bytes.Buffer)
	hash.Write(salt)
	hash.Write(key)

	out := hash.Bytes()
	if len(out) != hashTotalLength {
		return nil, errors.New("written bytes do not match header size")
	}
	return out, nil
}

// ComparePBKDF2HashAndPassword verifies if the hashed password matches the provided plain password.
func ComparePBKDF2HashAndPassword(hash []byte, password []byte) error {
	if len(hash) != hashTotalLength {
		return fmt.Errorf("hashedPassword is invalid")
	}

	// Read from hash
	// SALT|KEY
	salt := hash[:hashSaltLength]
	keyFromHash := hash[hashSaltLength:hashTotalLength]
	keyFromPassword := stretchPassword(password, salt, hashIterations, hashKeyLength)
	if !hmac.Equal(keyFromHash, keyFromPassword) {
		return ErrMismatchedHashAndPassword
	}

	return nil
}
