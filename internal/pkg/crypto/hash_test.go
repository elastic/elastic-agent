// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package crypto

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// Fuzzy test for GenerateFromPassword and ComparePBKDF2HashAndPassword
func FuzzGenerateAndCompare(f *testing.F) {
	// Seed the fuzzer with a few example passwords
	f.Add("password123")
	f.Add("123456")
	f.Add("!@#$%^&*()_+-=")
	f.Add("longpasswordwith1234567890and@symbols")
	f.Add("short")
	f.Add("V2tzU2c1UUJka2Q5blFyUUJqY1c6V294dlEtWXVUV3FQajZBbzdSd0JWUQ==")

	f.Fuzz(func(t *testing.T, password string) {
		if len(password) == 0 {
			// Skip empty passwords to avoid unnecessary checks
			return
		}

		t.Log("Testing password:", password)

		// Generate hashed password
		hash, err := GeneratePBKDF2FromPassword([]byte(password))
		if err != nil {
			t.Errorf("Failed to generate hashed password: %v", err)
			return
		}

		// Verify the hashed password
		err = ComparePBKDF2HashAndPassword(hash, []byte(password))
		require.NoError(t, err, "Password verification failed")

		// Negative test: modify the password slightly and check verification fails
		modifiedPassword := password + "wrong"
		err = ComparePBKDF2HashAndPassword(hash, []byte(modifiedPassword))
		require.ErrorIs(t, err, ErrMismatchedHashAndPassword, "Password verification succeeded")
	})
}
