// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package cmd

import (
	"testing"
)

func TestGetFleetInput(t *testing.T) {
	tests := []struct {
		name   string
		input  map[string]interface{}
		expect map[string]interface{}
	}{{
		name: "fleet-server input found",
		input: map[string]interface{}{
			"inputs": []map[string]interface{}{
				map[string]interface{}{
					"type": "fleet-server",
				}},
		},
		expect: map[string]interface{}{
			"type": "fleet-server",
		},
	}, {
		name: "no fleet-server input",
		input: map[string]interface{}{
			"inputs": []map[string]interface{}{
				map[string]interface{}{
					"type": "test-server",
				}},
		},
		expect: nil,
	}, {
		name: "wrong input formant",
		input: map[string]interface{}{
			"inputs": "example",
		},
		expect: nil,
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := getFleetInput(tt.input)
			if tt.expect == nil && r != nil {
				t.Error("expected nil")
			}
		})
	}
}
