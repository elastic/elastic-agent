// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package translate

import (
	"errors"
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

// A unit's status comes only from what the receiver reports for it, never from
// the receiver's top-level status, which aggregates all its monitors.
func TestGetComponentStateControlProtocolUnitStatus(t *testing.T) {
	unit := func(id string, streams ...map[string]any) component.Unit {
		anyStreams := make([]any, 0, len(streams))
		for _, stream := range streams {
			anyStreams = append(anyStreams, stream)
		}
		return component.Unit{
			ID:   id,
			Type: client.UnitTypeInput,
			Config: component.MustExpectedConfig(map[string]any{
				"id":      id,
				"type":    "synthetics/browser",
				"streams": anyStreams,
			}),
		}
	}
	// A monitor from the Synthetics app, reported under its stream ID. Only its
	// first stream is a monitor.
	appBrowser := unit("synthetics/browser-app",
		map[string]any{"id": "app-monitor", "type": "browser", "origin": "ui"},
		map[string]any{"id": "app-monitor-network", "data_stream": map[string]any{"dataset": "browser.network"}},
		map[string]any{"id": "app-monitor-screenshot", "data_stream": map[string]any{"dataset": "browser.screenshot"}},
	)
	// A monitor from the integration, reported under its unit ID.
	legacyBrowser := unit("synthetics/browser-legacy",
		map[string]any{"id": "legacy-monitor", "type": "browser"},
		map[string]any{"id": "legacy-monitor-network", "data_stream": map[string]any{"dataset": "browser.network"}},
		map[string]any{"id": "legacy-monitor-screenshot", "data_stream": map[string]any{"dataset": "browser.screenshot"}},
	)
	failing := unit("synthetics/browser-failing", map[string]any{"id": "failing-monitor", "type": "browser", "origin": "ui"})
	// A monitor the receiver hasn't run yet.
	pending := unit("synthetics/browser-pending", map[string]any{"id": "pending-monitor", "type": "browser", "origin": "ui"})

	comp := controlProtocolComponent()
	comp.Units = []component.Unit{appBrowser, legacyBrowser, failing, pending}

	inputStatus := func(inputs pcommon.Map, id string, status componentstatus.Status, err string) {
		input := inputs.PutEmptyMap(id)
		input.PutStr("status", status.String())
		input.PutStr("error", err)
	}
	receiverKey := fmt.Sprintf("receiver:heartbeatreceiver/%ssynthetics/tcp-default/single", OtelNamePrefix)
	pipelineStatus := func(receiver *componentstatus.Event) *status.AggregateStatus {
		return &status.AggregateStatus{
			Event:              receiver,
			ComponentStatusMap: map[string]*status.AggregateStatus{receiverKey: {Event: receiver}},
		}
	}
	unitState := func(t *testing.T, state runtime.ComponentComponentState, u component.Unit) runtime.ComponentUnitState {
		unitState, ok := state.State.Units[runtime.ComponentUnitKey{UnitID: u.ID, UnitType: client.UnitTypeInput}]
		require.True(t, ok, "no state for unit %s", u.ID)
		return unitState
	}

	t.Run("reported", func(t *testing.T) {
		attrs := pcommon.NewMap()
		inputs := attrs.PutEmptyMap("inputs")
		inputStatus(inputs, "app-monitor", componentstatus.StatusOK, "")
		inputStatus(inputs, "synthetics/browser-legacy", componentstatus.StatusOK, "")
		inputStatus(inputs, "failing-monitor", componentstatus.StatusPermanentError, "browser crashed")
		// The receiver's top-level status is the worst of its monitors.
		receiver := componentstatus.NewEvent(componentstatus.StatusPermanentError,
			componentstatus.WithError(errors.New("browser crashed")), componentstatus.WithAttributes(attrs))

		result, err := getComponentState(pipelineStatus(receiver), comp)
		require.NoError(t, err)

		app := unitState(t, result, appBrowser)
		assert.Equal(t, client.UnitStateHealthy, app.State)
		assert.Equal(t, map[string]any{"streams": map[string]map[string]string{
			"app-monitor": {"error": "", "status": client.UnitStateHealthy.String()},
		}}, app.Payload, "only the monitor's own stream should have a status")

		legacy := unitState(t, result, legacyBrowser)
		assert.Equal(t, client.UnitStateHealthy, legacy.State)
		assert.Equal(t, map[string]any{"streams": map[string]map[string]string{
			"legacy-monitor": {"error": "", "status": client.UnitStateHealthy.String()},
		}}, legacy.Payload, "a status reported under the unit ID should belong to the monitor's stream")

		failed := unitState(t, result, failing)
		assert.Equal(t, client.UnitStateFailed, failed.State)
		assert.Contains(t, failed.Message, "browser crashed")

		notRun := unitState(t, result, pending)
		assert.Equal(t, client.UnitStateStarting, notRun.State, "a unit the receiver doesn't report on shouldn't get another monitor's status")
		assert.Equal(t, controlProtocolUnitNotReportedMessage, notRun.Message)
	})

	t.Run("receiver failed without per-input statuses", func(t *testing.T) {
		receiver := componentstatus.NewEvent(componentstatus.StatusPermanentError, componentstatus.WithError(errors.New("failed to start")))
		result, err := getComponentState(pipelineStatus(receiver), comp)
		require.NoError(t, err)
		for _, u := range comp.Units {
			state := unitState(t, result, u)
			assert.Equal(t, client.UnitStateFailed, state.State, "the receiver's own error should apply to unit %s", u.ID)
			assert.Contains(t, state.Message, "failed to start")
		}
	})

	t.Run("receiver healthy without per-input statuses", func(t *testing.T) {
		result, err := getComponentState(pipelineStatus(componentstatus.NewEvent(componentstatus.StatusOK)), comp)
		require.NoError(t, err)
		for _, u := range comp.Units {
			state := unitState(t, result, u)
			assert.Equal(t, client.UnitStateStarting, state.State, "unit %s hasn't been run by the receiver", u.ID)
			assert.Equal(t, controlProtocolUnitNotReportedMessage, state.Message)
		}
	})
}
