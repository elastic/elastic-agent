// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package gcloud

import (
	"regexp"
	"strings"
	"testing"
)

func TestSanitizeInstanceName(t *testing.T) {
	validName := regexp.MustCompile(`^[a-z][a-z0-9-]*[a-z0-9]$`)
	suffixRe := regexp.MustCompile(`^(.*)-([0-9a-f]{8})$`)

	tests := []struct {
		name     string
		batchID  string
		wantBase string // what the sanitized part before the -<suffix> should be
	}{
		{
			name:     "simple lowercase",
			batchID:  "my-instance",
			wantBase: "my-instance",
		},
		{
			name:     "uppercase converted to lowercase",
			batchID:  "My-Instance",
			wantBase: "my-instance",
		},
		{
			name:     "invalid characters replaced with hyphens",
			batchID:  "my_instance.name@test",
			wantBase: "my-instance-name-test",
		},
		{
			name:     "starts with number gets vm prefix",
			batchID:  "123-instance",
			wantBase: "vm-123-instance",
		},
		{
			name:     "trailing hyphens removed",
			batchID:  "my-instance---",
			wantBase: "my-instance",
		},
		{
			// The sanitized base is truncated to leave room for "-<8hex>".
			// 63 total = 54 base + 1 hyphen + 8 hex.
			name:     "truncated to leave room for suffix",
			batchID:  "a" + strings.Repeat("b", 100),
			wantBase: "a" + strings.Repeat("b", 53),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := sanitizeInstanceName(tt.batchID)
			if err != nil {
				t.Fatalf("sanitizeInstanceName(%q) returned error: %v", tt.batchID, err)
			}
			if len(got) > 63 {
				t.Errorf("sanitizeInstanceName(%q) length = %d, exceeds 63 char limit: %q", tt.batchID, len(got), got)
			}
			if !validName.MatchString(got) {
				t.Errorf("sanitizeInstanceName(%q) = %q, not a valid GCE name", tt.batchID, got)
			}
			m := suffixRe.FindStringSubmatch(got)
			if m == nil {
				t.Fatalf("sanitizeInstanceName(%q) = %q, missing 8-hex suffix", tt.batchID, got)
			}
			if m[1] != tt.wantBase {
				t.Errorf("sanitizeInstanceName(%q) base = %q, want %q", tt.batchID, m[1], tt.wantBase)
			}
		})
	}

	t.Run("empty batch id returns error", func(t *testing.T) {
		_, err := sanitizeInstanceName("")
		if err == nil {
			t.Errorf("sanitizeInstanceName(\"\") = nil error, want error")
		}
	})

	t.Run("two calls yield different suffixes", func(t *testing.T) {
		a, err := sanitizeInstanceName("windows-amd64-2022-default")
		if err != nil {
			t.Fatal(err)
		}
		b, err := sanitizeInstanceName("windows-amd64-2022-default")
		if err != nil {
			t.Fatal(err)
		}
		if a == b {
			t.Errorf("sanitizeInstanceName produced identical names on consecutive calls: %q", a)
		}
	})
}
