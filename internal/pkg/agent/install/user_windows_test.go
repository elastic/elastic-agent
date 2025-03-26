// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build windows

package install

import (
	"fmt"
	"strings"
	"testing"
	"unicode"

	"github.com/stretchr/testify/assert"
)

func TestPasswordCharSets(t *testing.T) {
	for _, tc := range []struct {
		name    string
		charSet string
		valid   func(rune) error
	}{
		{
			name:    "lowercase characters",
			charSet: passwordCharsLower,
			valid: func(r rune) error {
				if unicode.IsLower(r) {
					return nil
				}
				return fmt.Errorf("character %q is not lowercase", r)
			},
		},
		{
			name:    "uppercase characters",
			charSet: passwordCharsUpper,
			valid: func(r rune) error {
				if unicode.IsUpper(r) {
					return nil
				}
				return fmt.Errorf("character %q is not uppercase", r)
			},
		},
		{
			name:    "digit characters",
			charSet: passwordCharsDigits,
			valid: func(r rune) error {
				if unicode.IsDigit(r) {
					return nil
				}
				return fmt.Errorf("character %q is not a digit", r)
			},
		},
		{
			name:    "special characters",
			charSet: passwordCharsSpecial,
			valid: func(r rune) error {
				if unicode.IsPunct(r) || unicode.IsSymbol(r) {
					return nil
				}
				return fmt.Errorf("character %q is not a special character", r)
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, char := range tc.charSet {
				assert.NoError(t, tc.valid(char))
			}
		})
	}
}

// TestRandomPassword tries to ensure that generated passwords meet the windows security constraints.
func TestRandomPassword(t *testing.T) {
	const testTimes = 100000
	passwords := make(map[string]struct{})
	for i := 0; i < testTimes; i++ {
		password, err := RandomPassword()
		if err != nil {
			t.Fatalf("RandomPassword() returned an error: %v", err)
		}

		length := len(password)
		if length < passwordMinLength || length > passwordMaxLength {
			t.Fatalf("password %q is not within the allowed length range", password)
		}

		hasLower := false
		hasUpper := false
		hasDigit := false
		hasSpecial := false

		if strings.ContainsRune(password, 0) {
			t.Fatalf("password %q contains null character", password)
		}

		for _, char := range password {
			switch {
			case strings.ContainsRune(passwordCharsLower, char):
				hasLower = true
			case strings.ContainsRune(passwordCharsUpper, char):
				hasUpper = true
			case strings.ContainsRune(passwordCharsDigits, char):
				hasDigit = true
			case strings.ContainsRune(passwordCharsSpecial, char):
				hasSpecial = true
			default:
				t.Fatalf("password %q contains an invalid character %q (hasLower=%v, hasUpper=%v, hasDigit=%v, hasSpecial=%v)",
					password, string(char), hasLower, hasUpper, hasDigit, hasSpecial)
			}
		}

		if !hasLower || !hasUpper || !hasDigit || !hasSpecial {
			t.Fatalf("password %q does not contain all required character categories", password)
		}

		// Check for consecutive duplicate digits
		for j := 1; j < length; j++ {
			if password[j] == password[j-1] {
				t.Fatalf("password %q contains consecutive duplicate digits %q at positions %d %d", password, password[j], j, j-1)
			}
		}

		if _, exists := passwords[password]; exists {
			t.Fatalf("password %q is not unique", password)
		}
		passwords[password] = struct{}{}
	}
}
