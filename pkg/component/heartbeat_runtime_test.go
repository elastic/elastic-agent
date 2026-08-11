// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package component

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/elastic/elastic-agent-libs/logp"
)

// TestHeartbeatDefaultsToProcessUntilOTelParity protects the process runtime
// fallback for the known OTel parity gaps tracked in #16130. When those gaps are
// fixed, these cases should be updated to exercise the corrected OTel behavior
// before Heartbeat is made an OTel receiver by default again.
func TestHeartbeatDefaultsToProcessUntilOTelParity(t *testing.T) {
	platform := PlatformDetail{
		Platform: Platform{
			OS:   Linux,
			Arch: AMD64,
			GOOS: Linux,
		},
	}

	tests := []struct {
		name      string
		inputType string
		inputs    []interface{}
		validate  func(t *testing.T, component Component)
	}{
		{
			name:      "multiple monitors share the process scheduler limits",
			inputType: "synthetics/browser",
			inputs: []interface{}{
				heartbeatInput("synthetics/browser", "browser-1", map[string]interface{}{
					"schedule": "@every 1m",
				}),
				heartbeatInput("synthetics/browser", "browser-2", map[string]interface{}{
					"schedule": "@every 1m",
				}),
			},
			validate: func(t *testing.T, component Component) {
				var inputUnits int
				for _, unit := range component.Units {
					if unit.Type == client.UnitTypeInput {
						inputUnits++
					}
				}
				assert.Equal(t, 2, inputUnits, "both monitors should share one Heartbeat process")
			},
		},
		{
			name:      "managed monitor state remains on the process state loader path",
			inputType: "synthetics/http",
			inputs: []interface{}{
				heartbeatInput("synthetics/http", "http-1", map[string]interface{}{
					"schedule": "@every 1m",
					"urls":     []interface{}{"https://example.com"},
				}),
			},
		},
		{
			name:      "browser parameter names with dots stay on the preserving parser path",
			inputType: "synthetics/browser",
			inputs: []interface{}{
				heartbeatInput("synthetics/browser", "browser-dotted-params", map[string]interface{}{
					"schedule": "@every 1m",
					"params": map[string]interface{}{
						"subdomain.example.com": "literal-value",
					},
				}),
			},
			validate: func(t *testing.T, component Component) {
				inputUnit := findInputUnit(t, component)
				streams, ok := inputUnit.Config.Source.AsMap()["streams"].([]interface{})
				require.True(t, ok)
				require.Len(t, streams, 1)
				stream, ok := streams[0].(map[string]interface{})
				require.True(t, ok)
				params, ok := stream["params"].(map[string]interface{})
				require.True(t, ok)
				assert.Equal(t, "literal-value", params["subdomain.example.com"])
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runtimeSpecs, err := NewRuntimeSpecs(platform, []InputRuntimeSpec{
				{
					InputType:  tt.inputType,
					BinaryName: "elastic-otel-collector",
					Spec: InputSpec{
						Name:      tt.inputType,
						Platforms: []string{platform.String()},
						Outputs:   []string{"elasticsearch"},
						Command: &CommandSpec{
							Args: []string{"heartbeat"},
						},
					},
				},
			})
			require.NoError(t, err)

			components, err := runtimeSpecs.ToComponents(
				map[string]interface{}{
					"outputs": map[string]interface{}{
						"default": map[string]interface{}{
							"type":    "elasticsearch",
							"enabled": true,
						},
					},
					"inputs": tt.inputs,
				},
				DefaultRuntimeConfig(), nil, nil, logp.InfoLevel, nil,
				map[string]uint64{}, map[string]bool{},
			)
			require.NoError(t, err)
			require.Len(t, components, 1)
			assert.Equal(t, ProcessRuntimeManager, components[0].RuntimeManager)

			if tt.validate != nil {
				tt.validate(t, components[0])
			}
		})
	}
}

func heartbeatInput(inputType, id string, streamConfig map[string]interface{}) map[string]interface{} {
	streamConfig["id"] = id + "-stream"
	return map[string]interface{}{
		"type":       inputType,
		"id":         id,
		"use_output": "default",
		"streams":    []interface{}{streamConfig},
	}
}

func findInputUnit(t *testing.T, component Component) Unit {
	t.Helper()
	for _, unit := range component.Units {
		if unit.Type == client.UnitTypeInput {
			return unit
		}
	}
	t.Fatal("component has no input unit")
	return Unit{}
}
