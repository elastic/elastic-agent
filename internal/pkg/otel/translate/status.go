// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package translate

import (
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/open-telemetry/opentelemetry-collector-contrib/pkg/status"
	otelcomponent "go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/component/componentstatus"
	"go.opentelemetry.io/collector/pipeline"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/elastic/elastic-agent/pkg/component"
	"github.com/elastic/elastic-agent/pkg/component/runtime"
	"github.com/elastic/elastic-agent/version"
)

const OtelComponentName = "beats-receiver"

// GetAllComponentStates extracts all the component states represented by the given otel status, for the provided components.
// If a state doesn't exist for a component, we return a synthetic STOPPED state.
func GetAllComponentStates(otelStatus *status.AggregateStatus, components []component.Component) ([]runtime.ComponentComponentState, error) {
	var componentStates []runtime.ComponentComponentState
	otelPipelineStatus, err := getOtelRuntimePipelineStatuses(otelStatus)
	if err != nil {
		return nil, err
	}
	for _, comp := range components {
		if comp.RuntimeManager == component.OtelRuntimeManager {
			var compState runtime.ComponentComponentState
			if pipelineStatus, found := otelPipelineStatus[comp.ID]; found {
				var statusErr error
				if compState, statusErr = getComponentState(pipelineStatus, comp); statusErr != nil {
					return nil, statusErr
				}
			} else {
				// If the component is not found in the OTel status, we return a stopped state.
				compState = runtime.ComponentComponentState{
					Component: comp,
					State: runtime.ComponentState{
						State: client.UnitStateStopped,
					},
				}
			}
			componentStates = append(componentStates, compState)
		}
	}
	return componentStates, nil
}

// DropComponentStateFromOtelStatus removes the statuses of otel pipelines representing runtime components from the
// given status.
func DropComponentStateFromOtelStatus(otelStatus *status.AggregateStatus) error {
	if otelStatus == nil {
		return nil
	}
	for pipelineStatusId := range otelStatus.ComponentStatusMap {
		pipelineId := &pipeline.ID{}
		componentKind, pipelineIdStr := parseEntityStatusId(pipelineStatusId)
		if componentKind != "pipeline" {
			return fmt.Errorf("pipeline status id %s is not a pipeline", pipelineStatusId)
		}
		err := pipelineId.UnmarshalText([]byte(pipelineIdStr)) // there's no ergonomic way to do this conversion
		if err != nil {
			return err
		}
		if strings.HasPrefix(pipelineId.Name(), OtelNamePrefix) {
			delete(otelStatus.ComponentStatusMap, pipelineStatusId)
		}
	}

	return nil
}

// getOtelRuntimePipelineStatuses finds otel pipeline statuses belonging to runtime components and returns them as a map
// from component id to pipeline status.
func getOtelRuntimePipelineStatuses(otelStatus *status.AggregateStatus) (map[string]*status.AggregateStatus, error) {
	if otelStatus == nil {
		return map[string]*status.AggregateStatus{}, nil
	}

	pipelines := make(map[string]*status.AggregateStatus, len(otelStatus.ComponentStatusMap))

	for pipelineStatusId, pipelineStatus := range otelStatus.ComponentStatusMap {
		pipelineId := &pipeline.ID{}
		componentKind, pipelineIdStr := parseEntityStatusId(pipelineStatusId)
		if componentKind != "pipeline" {
			return nil, fmt.Errorf("pipeline status id %s is not a pipeline", pipelineStatusId)
		}
		err := pipelineId.UnmarshalText([]byte(pipelineIdStr)) // there's no ergonomic way to do this conversion
		if err != nil {
			return nil, err
		}
		if componentID, found := strings.CutPrefix(pipelineId.Name(), OtelNamePrefix); found {
			pipelines[componentID] = pipelineStatus
		}

	}
	return pipelines, nil
}

// getComponentState extracts the full status of a component from its respective otel pipeline status.
func getComponentState(pipelineStatus *status.AggregateStatus, comp component.Component) (runtime.ComponentComponentState, error) {
	compState := runtime.ComponentState{
		State:   otelStatusToUnitState(pipelineStatus.Status()),
		Message: pipelineStatus.Status().String(),
		Units:   make(map[runtime.ComponentUnitKey]runtime.ComponentUnitState),
		VersionInfo: runtime.ComponentVersionInfo{
			Name: OtelComponentName,
			Meta: map[string]string{ // mimic what beats return over the control protocol
				"build_time": version.BuildTime().String(),
				"commit":     version.Commit(),
			},
			BuildHash: version.Commit(),
		},
	}
	receiverStatuses, exporterStatuses, err := getUnitOtelStatuses(pipelineStatus)
	if err != nil {
		return runtime.ComponentComponentState{}, err
	}

	// We either have one receiver and exporter, or none. Multiple receivers or exporters are a logic error.
	// If there's no receiver or exporter, we simply don't set a status for it.
	var receiverStatus, exporterStatus *status.AggregateStatus
	if len(receiverStatuses) > 1 {
		return runtime.ComponentComponentState{}, fmt.Errorf("expected at most one receiver for component %s, found %d", comp.ID, len(receiverStatuses))
	} else if len(receiverStatuses) == 1 {
		receiverStatus = slices.Collect(maps.Values(receiverStatuses))[0]
	}

	if len(exporterStatuses) > 1 {
		return runtime.ComponentComponentState{}, fmt.Errorf("expected at most one exporter for component %s, found %d", comp.ID, len(exporterStatuses))
	} else if len(exporterStatuses) == 1 {
		exporterStatus = slices.Collect(maps.Values(exporterStatuses))[0]
	}

	for _, unit := range comp.Units {
		unitKey := runtime.ComponentUnitKey{
			UnitID:   unit.ID,
			UnitType: unit.Type,
		}
		switch unit.Type {
		case client.UnitTypeInput:
			if receiverStatus != nil {
				compState.Units[unitKey] = getComponentUnitState(receiverStatus, unit)
			}
		case client.UnitTypeOutput:
			if exporterStatus != nil {
				compState.Units[unitKey] = getComponentUnitState(exporterStatus, unit)
			}
		}
	}

	compStatus := runtime.ComponentComponentState{
		Component: comp,
		State:     compState,
	}
	return compStatus, nil
}

// getUnitOtelStatuses extracts the receiver and exporter status from otel pipeline status.
func getUnitOtelStatuses(pipelineStatus *status.AggregateStatus) (
	receiverStatuses map[otelcomponent.ID]*status.AggregateStatus,
	exporterStatuses map[otelcomponent.ID]*status.AggregateStatus,
	err error) {
	receiverStatuses = make(map[otelcomponent.ID]*status.AggregateStatus)
	exporterStatuses = make(map[otelcomponent.ID]*status.AggregateStatus)

	for otelCompStatusId, otelCompStatus := range pipelineStatus.ComponentStatusMap {
		var otelComponentID otelcomponent.ID
		componentKind, otelComponentIDStr := parseEntityStatusId(otelCompStatusId)
		err := otelComponentID.UnmarshalText([]byte(otelComponentIDStr))
		if err != nil {
			return nil, nil, err
		}

		switch componentKind {
		case "receiver":
			receiverStatuses[otelComponentID] = otelCompStatus
		case "exporter":
			exporterStatuses[otelComponentID] = otelCompStatus
		}
	}

	return
}

// getComponentUnitState extracts component unit state from otel status.
func getComponentUnitState(otelUnitStatus *status.AggregateStatus, unit component.Unit) runtime.ComponentUnitState {
	unitStatus := otelStatusToUnitState(otelUnitStatus.Status())
	var streamStatus map[string]map[string]string

	if unit.Config != nil {
		streamStatus = make(map[string]map[string]string, len(unit.Config.Streams))
		for _, stream := range unit.Config.Streams {
			// For now, set the stream status to the same as the unit status.
			var errorString string
			if otelUnitStatus.Err() != nil {
				errorString = otelUnitStatus.Err().Error()
			}
			streamStatus[stream.Id] = map[string]string{
				"error":  errorString,
				"status": unitStatus.String(),
			}
		}
	}

	var payload map[string]any
	if len(streamStatus) > 0 {
		payload = map[string]any{
			"streams": streamStatus,
		}
	}

	return runtime.ComponentUnitState{
		State:   unitStatus,
		Message: unitStatus.String(),
		Payload: payload,
	}
}

// otelStatusToUnitState translates otel status to component unit state.
func otelStatusToUnitState(status componentstatus.Status) client.UnitState {
	statusMap := map[componentstatus.Status]client.UnitState{
		componentstatus.StatusNone: client.UnitStateDegraded,
		// StatusStarting indicates the component is starting.
		componentstatus.StatusStarting: client.UnitStateStarting,
		// StatusOK indicates the component is running without issues.
		componentstatus.StatusOK: client.UnitStateHealthy,
		// StatusRecoverableError indicates that the component has experienced a transient error and may recover.
		componentstatus.StatusRecoverableError: client.UnitStateDegraded,
		// StatusPermanentError indicates that the component has detected a condition at runtime that will need human intervention to fix. The collector will continue to run in a degraded mode.
		componentstatus.StatusPermanentError: client.UnitStateFailed,
		// StatusFatalError indicates that the collector has experienced a fatal runtime error and will shut down.
		componentstatus.StatusFatalError: client.UnitStateFailed,
		// StatusStopping indicates that the component is in the process of shutting down.
		componentstatus.StatusStopping: client.UnitStateStopping,
		// StatusStopped indicates that the component has completed shutdown.
		componentstatus.StatusStopped: client.UnitStateStopped,
	}
	return statusMap[status]
}

// parseEntityStatusId parses an entity status ID into its kind and entity ID. An entity can be a pipeline or otel component.
// The ID is expected to be in the format "kind:entityId", where kind is either "pipeline" or the otel component type (e.g., "receiver", "exporter").
// This format is used by the healthcheckv2 extension.
func parseEntityStatusId(id string) (kind string, entityId string) {
	parts := strings.SplitN(id, ":", 2)
	if len(parts) != 2 {
		return "", ""
	}
	return parts[0], parts[1]
}
