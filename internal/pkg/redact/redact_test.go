package redact

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRedactSecretPaths(t *testing.T) {
	tests := []struct {
		name     string
		input    map[string]any
		expected map[string]any
	}{
		{
			name: "no secret paths",
			input: map[string]any{
				"username": "user",
				"email":    "user@example.com",
			},
			expected: map[string]any{
				"username": "user",
				"email":    "user@example.com",
			},
		},
		{
			name: "simple secret paths",
			input: map[string]any{
				"secret_paths": []any{"password", "token"},
				"password":     "mysecretpassword",
				"token":        "mysecrettoken",
				"username":     "user",
			},
			expected: map[string]any{
				"secret_paths": []any{"password", "token"},
				"password":     "<REDACTED>",
				"token":        "<REDACTED>",
				"username":     "user",
			},
		},
		{
			name: "nested secret paths",
			input: map[string]any{
				"secret_paths": []any{"credentials.password", "credentials.token"},
				"credentials": map[string]any{
					"password": "mysecretpassword",
					"token":    "mysecrettoken",
					"username": "user",
				},
			},
			expected: map[string]any{
				"secret_paths": []any{"credentials.password", "credentials.token"},
				"credentials": map[string]any{
					"password": "<REDACTED>",
					"token":    "<REDACTED>",
					"username": "user",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var errOut bytes.Buffer
			result := RedactSecretPaths(tt.input, &errOut)
			assert.Equal(t, tt.expected, result)
			assert.Empty(t, errOut.String())
		})
	}
}

func TestRedactPossibleSecrets(t *testing.T) {
	tests := []struct {
		name     string
		input    map[string]any
		expected map[string]any
	}{
		{
			name: "redact in simple map",
			input: map[string]any{
				"password": "mysecretpassword",
				"Token":    "mysecrettoken",
				"username": "user",
			},
			expected: map[string]any{
				"password": "<REDACTED>",
				"Token":    "<REDACTED>",
				"username": "user",
			},
		},
		{
			name: "no sensitive keys",
			input: map[string]any{
				"username": "user",
				"email":    "user@example.com",
			},
			expected: map[string]any{
				"username": "user",
				"email":    "user@example.com",
			},
		},
		{
			name: "redact in lists",
			input: map[string]any{
				"inputs": []any{
					map[string]any{
						"name":   "input1",
						"apiKey": "input1api",
					},
				},
			},
			expected: map[string]any{
				"inputs": []any{
					map[string]any{
						"name":   "input1",
						"apiKey": "<REDACTED>",
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var errOut bytes.Buffer
			result := RedactPossibleSecrets(tt.input, &errOut)
			assert.Equal(t, tt.expected, result)
			assert.Empty(t, errOut.String())
		})
	}
}
