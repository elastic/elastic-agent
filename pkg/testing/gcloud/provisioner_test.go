// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package gcloud

import (
	"strings"
	"testing"
)

func TestSanitizeInstanceName(t *testing.T) {
	tests := []struct {
		name     string
		batchID  string
		expected string
	}{
		{
			name:     "simple lowercase",
			batchID:  "my-instance",
			expected: "my-instance",
		},
		{
			name:     "uppercase converted to lowercase",
			batchID:  "My-Instance",
			expected: "my-instance",
		},
		{
			name:     "invalid characters replaced with hyphens",
			batchID:  "my_instance.name@test",
			expected: "my-instance-name-test",
		},
		{
			name:     "starts with number gets vm prefix",
			batchID:  "123-instance",
			expected: "vm-123-instance",
		},
		{
			name:     "starts with hyphen gets vm prefix",
			batchID:  "-instance",
			expected: "vm--instance",
		},
		{
			name:     "truncated to 63 characters",
			batchID:  "a" + strings.Repeat("b", 100),
			expected: "a" + strings.Repeat("b", 62),
		},
		{
			name:     "trailing hyphens removed",
			batchID:  "my-instance---",
			expected: "my-instance",
		},
		{
			name:     "trailing hyphens removed after truncation",
			batchID:  strings.Repeat("a", 60) + "---bbb",
			expected: strings.Repeat("a", 60),
		},
		{
			name:     "numeric prefix with truncation",
			batchID:  "9" + strings.Repeat("a", 100),
			expected: "vm-9" + strings.Repeat("a", 59),
		},
		{
			name:     "empty string",
			batchID:  "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sanitizeInstanceName(tt.batchID)
			if got != tt.expected {
				t.Errorf("sanitizeInstanceName(%q) = %q, want %q", tt.batchID, got, tt.expected)
			}
			if len(got) > 63 {
				t.Errorf("sanitizeInstanceName(%q) length = %d, exceeds 63 char limit", tt.batchID, len(got))
			}
		})
	}
}
