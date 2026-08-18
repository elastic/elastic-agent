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

func TestHeartbeatBrowserParamsPreserveDottedKeys(t *testing.T) {
	platform := PlatformDetail{
		Platform: Platform{
			OS:   Linux,
			Arch: AMD64,
			GOOS: Linux,
		},
	}

	runtimeSpecs, err := NewRuntimeSpecs(platform, []InputRuntimeSpec{
		{
			InputType:  "synthetics/browser",
			BinaryName: "elastic-otel-collector",
			Spec: InputSpec{
				Name:      "synthetics/browser",
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
			"inputs": []interface{}{
				heartbeatInput("synthetics/browser", "browser-dotted-params", map[string]interface{}{
					"schedule": "@every 1m",
					"params": map[string]interface{}{
						"subdomain.example.com": "literal-value",
					},
				}),
			},
		},
		DefaultRuntimeConfig(), nil, nil, logp.InfoLevel, nil,
		map[string]uint64{}, map[string]bool{},
	)
	require.NoError(t, err)
	require.Len(t, components, 1)

	inputUnit := findInputUnit(t, components[0])
	streams, ok := inputUnit.Config.Source.AsMap()["streams"].([]interface{})
	require.True(t, ok)
	require.Len(t, streams, 1)
	stream, ok := streams[0].(map[string]interface{})
	require.True(t, ok)
	params, ok := stream["params"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "literal-value", params["subdomain.example.com"])
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
