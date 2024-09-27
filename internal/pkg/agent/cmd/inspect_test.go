// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package cmd

import (
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRedactSecretPaths(t *testing.T) {
	tests := []struct {
		name   string
		input  map[string]interface{}
		expect map[string]interface{}
	}{{
		name: "no secret_paths",
		input: map[string]interface{}{
			"outputs": map[string]interface{}{
				"default": map[string]interface{}{
					"type":    "elasticsearch",
					"api_key": "apikeyvalue",
				},
			},
			"inputs": []interface{}{
				map[string]interface{}{
					"type":   "example",
					"secret": "secretvalue",
				},
			},
		},
		expect: map[string]interface{}{
			"outputs": map[string]interface{}{
				"default": map[string]interface{}{
					"type":    "elasticsearch",
					"api_key": "apikeyvalue",
				},
			},
			"inputs": []interface{}{
				map[string]interface{}{
					"type":   "example",
					"secret": "secretvalue",
				},
			},
		},
	}, {
		name: "secret paths is not an array",
		input: map[string]interface{}{
			"secret_paths": "inputs.0.secret,outputs.default.api_key",
			"outputs": map[string]interface{}{
				"default": map[string]interface{}{
					"type":    "elasticsearch",
					"api_key": "apikeyvalue",
				},
			},
			"inputs": []interface{}{
				map[string]interface{}{
					"type":   "example",
					"secret": "secretvalue",
				},
			},
		},
		expect: map[string]interface{}{
			"secret_paths": "inputs.0.secret,outputs.default.api_key",
			"outputs": map[string]interface{}{
				"default": map[string]interface{}{
					"type":    "elasticsearch",
					"api_key": "apikeyvalue",
				},
			},
			"inputs": []interface{}{
				map[string]interface{}{
					"type":   "example",
					"secret": "secretvalue",
				},
			},
		},
	}, {
		name: "secret_paths are redacted",
		input: map[string]interface{}{
			"secret_paths": []interface{}{
				"inputs.0.secret",
				"outputs.default.api_key",
			},
			"outputs": map[string]interface{}{
				"default": map[string]interface{}{
					"type":    "elasticsearch",
					"api_key": "apikeyvalue",
				},
			},
			"inputs": []interface{}{
				map[string]interface{}{
					"type":   "example",
					"secret": "secretvalue",
				},
			},
		},
		expect: map[string]interface{}{
			"secret_paths": []interface{}{
				"inputs.0.secret",
				"outputs.default.api_key",
			},
			"outputs": map[string]interface{}{
				"default": map[string]interface{}{
					"type":    "elasticsearch",
					"api_key": "[REDACTED]",
				},
			},
			"inputs": []interface{}{
				map[string]interface{}{
					"type":   "example",
					"secret": "[REDACTED]",
				},
			},
		},
	}, {
		name: "secret_paths contains extra keys",
		input: map[string]interface{}{
			"secret_paths": []interface{}{
				"inputs.0.secret",
				"outputs.default.api_key",
				"inputs.1.secret",
			},
			"outputs": map[string]interface{}{
				"default": map[string]interface{}{
					"type":    "elasticsearch",
					"api_key": "apikeyvalue",
				},
			},
			"inputs": []interface{}{
				map[string]interface{}{
					"type":   "example",
					"secret": "secretvalue",
				},
			},
		},
		expect: map[string]interface{}{
			"secret_paths": []interface{}{
				"inputs.0.secret",
				"outputs.default.api_key",
				"inputs.1.secret",
			},
			"outputs": map[string]interface{}{
				"default": map[string]interface{}{
					"type":    "elasticsearch",
					"api_key": "[REDACTED]",
				},
			},
			"inputs": []interface{}{
				map[string]interface{}{
					"type":   "example",
					"secret": "[REDACTED]",
				},
			},
		},
	}, {
		name: "secret_paths contains non string key",
		input: map[string]interface{}{
			"secret_paths": []interface{}{
				"inputs.0.secret",
				"outputs.default.api_key",
				2,
			},
			"outputs": map[string]interface{}{
				"default": map[string]interface{}{
					"type":    "elasticsearch",
					"api_key": "apikeyvalue",
				},
			},
			"inputs": []interface{}{
				map[string]interface{}{
					"type":   "example",
					"secret": "secretvalue",
				},
			},
		},
		expect: map[string]interface{}{
			"secret_paths": []interface{}{
				"inputs.0.secret",
				"outputs.default.api_key",
				uint64(2), // go-ucfg serializing/deserializing flattens types
			},
			"outputs": map[string]interface{}{
				"default": map[string]interface{}{
					"type":    "elasticsearch",
					"api_key": "[REDACTED]",
				},
			},
			"inputs": []interface{}{
				map[string]interface{}{
					"type":   "example",
					"secret": "[REDACTED]",
				},
			},
		},
	}}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := redactSecretPaths(tc.input, io.Discard)
			assert.Equal(t, tc.expect, result)
		})
	}
}
