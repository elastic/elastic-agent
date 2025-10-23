// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package manager

import (
	"errors"
	"net"
	"path/filepath"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/pkg/component"

	"github.com/stretchr/testify/require"
)

func TestFindRandomPort(t *testing.T) {
	portCount := 2
	ports, err := findRandomTCPPorts(portCount)
	require.NoError(t, err)
	require.Len(t, ports, portCount)
	for _, port := range ports {
		assert.NotEqual(t, 0, port)
	}
	slices.Sort(ports)
	require.Len(t, slices.Compact(ports), portCount, "returned ports should be unique")

	defer func() {
		netListen = net.Listen
	}()

	netListen = func(string, string) (net.Listener, error) {
		return nil, errors.New("some error")
	}
	_, err = findRandomTCPPorts(portCount)
	assert.Error(t, err, "failed to find random port")
}

func testComponent(componentId string) component.Component {
	fileStreamConfig := map[string]any{
		"id":         "test",
		"use_output": "default",
		"streams": []any{
			map[string]any{
				"id": "test-1",
				"data_stream": map[string]any{
					"dataset": "generic-1",
				},
				"paths": []any{
					filepath.Join(paths.TempDir(), "nonexistent.log"),
				},
			},
			map[string]any{
				"id": "test-2",
				"data_stream": map[string]any{
					"dataset": "generic-2",
				},
				"paths": []any{
					filepath.Join(paths.TempDir(), "nonexistent.log"),
				},
			},
		},
	}

	esOutputConfig := map[string]any{
		"type":             "elasticsearch",
		"hosts":            []any{"localhost:9200"},
		"username":         "elastic",
		"password":         "password",
		"preset":           "balanced",
		"queue.mem.events": 3200,
	}

	return component.Component{
		ID:             componentId,
		RuntimeManager: component.OtelRuntimeManager,
		InputType:      "filestream",
		OutputType:     "elasticsearch",
		InputSpec: &component.InputRuntimeSpec{
			BinaryName: "agentbeat",
			Spec: component.InputSpec{
				Command: &component.CommandSpec{
					Args: []string{"filebeat"},
				},
			},
		},
		Units: []component.Unit{
			{
				ID:     "filestream-unit",
				Type:   client.UnitTypeInput,
				Config: component.MustExpectedConfig(fileStreamConfig),
			},
			{
				ID:     "filestream-default",
				Type:   client.UnitTypeOutput,
				Config: component.MustExpectedConfig(esOutputConfig),
			},
		},
	}
}
