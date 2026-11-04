// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package translate

import (
	"fmt"
	"testing"

	"github.com/open-telemetry/opentelemetry-collector-contrib/pkg/status"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/component/componentstatus"
	"go.opentelemetry.io/collector/pdata/pcommon"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/elastic/elastic-agent/pkg/component"
	"github.com/elastic/elastic-agent/pkg/component/runtime"
)

func controlProtocolComponent() component.Component {
	return component.Component{
		ID:             "synthetics/tcp-default",
		InputType:      "synthetics/tcp",
		OutputType:     "elasticsearch",
		RuntimeManager: component.OtelRuntimeManager,
		InputSpec: &component.InputRuntimeSpec{
			BinaryName: "elastic-otel-collector",
			Spec: component.InputSpec{
				Name: "synthetics/tcp",
				Command: &component.CommandSpec{
					Args: []string{"heartbeat"},
				},
				SingleReceiver:       true,
				ControlProtocolUnits: true,
			},
		},
		Units: []component.Unit{
			{
				ID:   "synthetics/tcp-monitor-a",
				Type: client.UnitTypeInput,
				Config: component.MustExpectedConfig(map[string]any{
					"id":   "synthetics/tcp-monitor-a",
					"type": "synthetics/tcp",
					"streams": []any{
						map[string]any{
							"id":       "monitor-a",
							"type":     "tcp",
							"hosts":    "localhost:9200",
							"schedule": "@every 1m",
						},
					},
				}),
			},
		},
	}
}

func TestGetReceiversConfigForControlProtocolComponent(t *testing.T) {
	comp := controlProtocolComponent()

	result, err := getReceiversConfigForComponent(&comp, nil, nil)
	require.NoError(t, err)
	require.Len(t, result, 1)

	receiverID, err := GetControlProtocolReceiverID(&comp)
	require.NoError(t, err)
	receiverConfig, ok := result[receiverID.String()].(map[string]any)
	require.True(t, ok, "expected one heartbeat receiver for the component, got %v", result)
	assert.Equal(t, map[string]any{"monitors": []map[string]any{}}, receiverConfig["heartbeat"],
		"monitors must come over the control protocol, not the receiver config")

	// Changing a monitor must not change the receiver config, so the collector keeps the receiver.
	changed := controlProtocolComponent()
	changed.Units[0].Config = component.MustExpectedConfig(map[string]any{
		"id":   "synthetics/tcp-monitor-a",
		"type": "synthetics/tcp",
		"streams": []any{
			map[string]any{
				"id":       "monitor-a",
				"type":     "tcp",
				"hosts":    "localhost:9300",
				"schedule": "@every 5m",
			},
		},
	})
	changedResult, err := getReceiversConfigForComponent(&changed, nil, nil)
	require.NoError(t, err)
	assert.Equal(t, result, changedResult)
}

func TestGetComponentStateControlProtocolComponent(t *testing.T) {
	comp := controlProtocolComponent()

	// Heartbeat reports the monitor under its input ID, not its stream ID.
	attrs := pcommon.NewMap()
	inputs := attrs.PutEmptyMap("inputs")
	monitor := inputs.PutEmptyMap("synthetics/tcp-monitor-a")
	monitor.PutStr("status", componentstatus.StatusRecoverableError.String())
	monitor.PutStr("error", "connection refused")

	receiverKey := fmt.Sprintf("receiver:heartbeatreceiver/%ssynthetics/tcp-default/single", OtelNamePrefix)
	pipelineStatus := &status.AggregateStatus{
		Event: componentstatus.NewEvent(componentstatus.StatusOK),
		ComponentStatusMap: map[string]*status.AggregateStatus{
			receiverKey: {Event: componentstatus.NewEvent(componentstatus.StatusOK, componentstatus.WithAttributes(attrs))},
		},
	}

	result, err := getComponentState(pipelineStatus, comp)
	require.NoError(t, err)
	unitState, ok := result.State.Units[runtime.ComponentUnitKey{UnitID: "synthetics/tcp-monitor-a", UnitType: client.UnitTypeInput}]
	require.True(t, ok)
	assert.Equal(t, client.UnitStateDegraded, unitState.State)
	streams, ok := unitState.Payload["streams"].(map[string]map[string]string)
	require.True(t, ok)
	assert.Equal(t, map[string]string{"error": "Recoverable: connection refused", "status": client.UnitStateDegraded.String()}, streams["monitor-a"])
}

// BenchmarkGetComponentStateManyMonitors measures one status update for a
// component whose receiver runs 1000 monitors, each in its own unit.
func BenchmarkGetComponentStateManyMonitors(b *testing.B) {
	const monitors = 1000
	comp := controlProtocolComponent()
	comp.Units = nil
	attrs := pcommon.NewMap()
	inputs := attrs.PutEmptyMap("inputs")
	for i := range monitors {
		inputID := fmt.Sprintf("synthetics/tcp-monitor-%04d", i)
		comp.Units = append(comp.Units, component.Unit{
			ID:   inputID,
			Type: client.UnitTypeInput,
			Config: component.MustExpectedConfig(map[string]any{
				"id":      inputID,
				"type":    "synthetics/tcp",
				"streams": []any{map[string]any{"id": fmt.Sprintf("monitor-%04d", i), "type": "tcp"}},
			}),
		})
		monitor := inputs.PutEmptyMap(inputID)
		monitor.PutStr("status", componentstatus.StatusOK.String())
		monitor.PutStr("error", "")
	}
	receiverKey := fmt.Sprintf("receiver:heartbeatreceiver/%ssynthetics/tcp-default/single", OtelNamePrefix)
	pipelineStatus := &status.AggregateStatus{
		Event: componentstatus.NewEvent(componentstatus.StatusOK),
		ComponentStatusMap: map[string]*status.AggregateStatus{
			receiverKey: {Event: componentstatus.NewEvent(componentstatus.StatusOK, componentstatus.WithAttributes(attrs))},
		},
	}

	for b.Loop() {
		result, err := getComponentState(pipelineStatus, comp)
		require.NoError(b, err)
		require.Len(b, result.State.Units, monitors)
	}
}
