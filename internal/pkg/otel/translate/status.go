// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package translate

import (
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/go-viper/mapstructure/v2"
	"github.com/open-telemetry/opentelemetry-collector-contrib/pkg/status"
	otelcomponent "go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/component/componentstatus"
	"go.opentelemetry.io/collector/pipeline"

	serializablestatus "github.com/elastic/elastic-agent/internal/pkg/otel/status"

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
			} else if otelStatus != nil && otelStatus.Event != nil && otelStatus.Status() == componentstatus.StatusStarting {
				compState = getComponentStartingState(comp)
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
func DropComponentStateFromOtelStatus(otelStatus *status.AggregateStatus) (*status.AggregateStatus, error) {
	if otelStatus == nil {
		return nil, nil
	}

	newStatus := deepCopyStatus(otelStatus)
	for pipelineStatusId := range newStatus.ComponentStatusMap {
		if pipelineStatusId == "extensions" {
			// we do not want to report extension status
			continue
		}
		pipelineId := &pipeline.ID{}
		componentKind, pipelineIdStr, parseErr := ParseEntityStatusId(pipelineStatusId)
		if parseErr != nil {
			return nil, parseErr
		}
		if componentKind == "extensions" {
			continue
		}
		if componentKind != "pipeline" {
			return nil, fmt.Errorf("pipeline status id %s is not a pipeline", pipelineStatusId)
		}
		err := pipelineId.UnmarshalText([]byte(pipelineIdStr)) // there's no ergonomic way to do this conversion
		if err != nil {
			return nil, err
		}
		if strings.HasPrefix(pipelineId.Name(), OtelNamePrefix) {
			delete(newStatus.ComponentStatusMap, pipelineStatusId)
		}
	}

	return newStatus, nil
}

// MaybeMuteExporterStatus modifies the given otel status by muting exporter statuses for muted components.
// It also updates parent pipeline statuses based on child components.
func MaybeMuteExporterStatus(
	otelStatus *status.AggregateStatus,
	components []component.Component,
) (*status.AggregateStatus, error) {
	if otelStatus == nil {
		return nil, nil
	}

	newStatus := deepCopyStatus(otelStatus)

	// Mute exporters
	if err := muteExporters(newStatus, components); err != nil {
		return nil, err
	}

	updateStatus(newStatus)

	return newStatus, nil
}

// HasStatus returns true when the status contains that component status.
func HasStatus(current *status.AggregateStatus, s componentstatus.Status) bool {
	if current == nil {
		return false
	}
	if current.Status() == s {
		return true
	}
	for _, comp := range current.ComponentStatusMap {
		return HasStatus(comp, s)
	}
	return false
}

// StateWithMessage returns a `client.UnitState` and message for the current status.
func StateWithMessage(current status.Event) (client.UnitState, string) {
	s := current.Status()
	switch s {
	case componentstatus.StatusNone:
		// didn't report a status, we assume with no status
		// that it is healthy
		return client.UnitStateHealthy, "Healthy"
	case componentstatus.StatusStarting:
		return client.UnitStateStarting, "Starting"
	case componentstatus.StatusOK:
		if current.Err() != nil && current.Err().Error() != "" {
			// our own implementation of status.Event can have errors form events with StatusOK, representing
			// informational diagnostic messages
			return client.UnitStateHealthy, current.Err().Error()
		}
		return client.UnitStateHealthy, "Healthy"
	case componentstatus.StatusRecoverableError:
		if current.Err() != nil {
			return client.UnitStateDegraded, fmt.Sprintf("Recoverable: %s", current.Err())
		}
		return client.UnitStateDegraded, "Unknown recoverable error"
	case componentstatus.StatusPermanentError:
		if current.Err() != nil {
			return client.UnitStateFailed, fmt.Sprintf("Permanent: %s", current.Err())
		}
		return client.UnitStateFailed, "Unknown permanent error"
	case componentstatus.StatusFatalError:
		if current.Err() != nil {
			return client.UnitStateFailed, fmt.Sprintf("Fatal: %s", current.Err())
		}
		return client.UnitStateFailed, "Unknown fatal error"
	case componentstatus.StatusStopping:
		return client.UnitStateStopping, "Stopping"
	case componentstatus.StatusStopped:
		return client.UnitStateStopped, "Stopped"
	}
	// if we hit this case, then a new status was added that we don't know about
	return client.UnitStateFailed, fmt.Sprintf("Unknown component status: %s", s)
}

// updateStatus recursively updates each AggregateStatus.Event
// based on the statuses of its child components.
func updateStatus(status *status.AggregateStatus) {
	if status == nil {
		return
	}

	ok := true

	for _, child := range status.ComponentStatusMap {
		updateStatus(child)

		if child.Status() != componentstatus.StatusOK {
			ok = false
		}
	}

	if len(status.ComponentStatusMap) > 0 {
		if ok {
			status.Event = componentstatus.NewEvent(componentstatus.StatusOK)
		}
	}
}

// muteExporters sets all exporter statuses to OK for muted pipelines/components.
func muteExporters(agg *status.AggregateStatus, components []component.Component) error {
	// Determine all exporter status IDs that should be muted based on components
	// with output status reporting disabled.
	mutedExporterStatusIDs := make(map[string]struct{})
	for _, comp := range components {
		if comp.OutputStatusReporting == nil || comp.OutputStatusReporting.Enabled {
			continue
		}
		exporterType, err := OutputTypeToExporterType(comp.OutputType)
		if err != nil {
			return err
		}
		exporterID := GetExporterID(exporterType, comp.OutputName)
		mutedExporterStatusIDs["exporter:"+exporterID.String()] = struct{}{}
	}

	// Mute the identified exporters in every pipeline.
	for pipelineStatusID, pipelineStatus := range agg.ComponentStatusMap {
		if pipelineStatusID == "extensions" {
			continue
		}
		for compID, compStatus := range pipelineStatus.ComponentStatusMap {
			if _, muted := mutedExporterStatusIDs[compID]; muted {
				compStatus.Event = componentstatus.NewEvent(componentstatus.StatusOK)
			}
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
		if pipelineStatusId == "extensions" {
			// we do not want to report extension status
			continue
		}
		pipelineId := &pipeline.ID{}
		componentKind, pipelineIdStr, parseErr := ParseEntityStatusId(pipelineStatusId)
		if parseErr != nil {
			return nil, parseErr
		}
		if componentKind == "extensions" {
			continue
		}
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
	pipelineState, pipelineMessage := StateWithMessage(pipelineStatus)
	compState := runtime.ComponentState{
		State:   pipelineState,
		Message: pipelineMessage,
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
	receiverStatuses, exporterStatuses, err := getUnitOtelStatuses(pipelineStatus, comp)
	if err != nil {
		return runtime.ComponentComponentState{}, err
	}

	// Build a map from input ID to receiver status. Each receiver corresponds to one input,
	// and its otel component ID encodes the input ID as compID/inputID.
	receiverByInputID := make(map[string]*status.AggregateStatus)
	receiverPrefix := OtelNamePrefix + comp.ID + "/"
	for receiverOtelID, rs := range receiverStatuses {
		if inputID, found := strings.CutPrefix(receiverOtelID.Name(), receiverPrefix); found {
			receiverByInputID[inputID] = rs
		}
	}

	var exporterStatus *status.AggregateStatus
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
			if len(receiverByInputID) > 0 {
				compState.Units[unitKey] = getComponentUnitState(nil, receiverByInputID, unit, &comp)
			}
		case client.UnitTypeOutput:
			if exporterStatus != nil {
				compState.Units[unitKey] = getComponentUnitState(exporterStatus, nil, unit, &comp)
			}
		}
	}

	compStatus := runtime.ComponentComponentState{
		Component: comp,
		State:     compState,
	}
	return compStatus, nil
}

// getStreamStatusFromReceiver extracts a stream's status from a receiver's "inputs" attributes.
func getStreamStatusFromReceiver(rs *status.AggregateStatus, streamID string) *serializablestatus.SerializableEvent {
	attrs := rs.Attributes().AsRaw()
	inputStatuses, ok := attrs["inputs"]
	if !ok {
		return nil
	}
	var inputStatusMap map[string]*serializablestatus.SerializableEvent
	if err := mapstructure.Decode(inputStatuses, &inputStatusMap); err != nil {
		return nil
	}
	return inputStatusMap[streamID]
}

// getComponentStartingState returns a ComponentComponentState with all units in the starting state,
// including version info and initial status for each unit.
func getComponentStartingState(comp component.Component) runtime.ComponentComponentState {
	compState := runtime.ComponentState{
		State:   client.UnitStateStarting,
		Message: client.UnitStateStarting.String(),
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
	for _, unit := range comp.Units {
		unitKey := runtime.ComponentUnitKey{
			UnitID:   unit.ID,
			UnitType: unit.Type,
		}
		compState.Units[unitKey] = getComponentUnitState(&status.AggregateStatus{
			Event:              componentstatus.NewEvent(componentstatus.StatusStarting),
			ComponentStatusMap: map[string]*status.AggregateStatus{},
		}, nil, unit, &comp)
	}
	return runtime.ComponentComponentState{
		Component: comp,
		State:     compState,
	}
}

// getUnitOtelStatuses extracts the receiver and exporter status from otel pipeline status.
func getUnitOtelStatuses(pipelineStatus *status.AggregateStatus, comp component.Component) (
	receiverStatuses map[otelcomponent.ID]*status.AggregateStatus,
	exporterStatuses map[otelcomponent.ID]*status.AggregateStatus,
	err error) {
	receiverStatuses = make(map[otelcomponent.ID]*status.AggregateStatus)
	exporterStatuses = make(map[otelcomponent.ID]*status.AggregateStatus)

	for otelCompStatusId, otelCompStatus := range pipelineStatus.ComponentStatusMap {
		var otelComponentID otelcomponent.ID
		componentKind, otelComponentIDStr, parseErr := ParseEntityStatusId(otelCompStatusId)
		if parseErr != nil {
			return nil, nil, parseErr
		}
		err = otelComponentID.UnmarshalText([]byte(otelComponentIDStr))
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
// For input units with streams, receiverByInputID maps each stream/input ID to its dedicated receiver status.
// For output units or starting state, otelUnitStatus provides a single status and receiverByInputID is nil.
func getComponentUnitState(otelUnitStatus *status.AggregateStatus, receiverByInputID map[string]*status.AggregateStatus, unit component.Unit, comp *component.Component) runtime.ComponentUnitState {
	if unit.Config == nil || unit.Type == client.UnitTypeOutput {
		topLevelState, topLevelMessage := StateWithMessage(otelUnitStatus)
		return runtime.ComponentUnitState{
			State:   topLevelState,
			Message: topLevelMessage,
		}
	}

	// unitStreamStatuses tracks per-stream statuses from receiver attributes (detailed status from beat)
	unitStreamStatuses := make(map[string]*serializablestatus.SerializableEvent, len(unit.Config.Streams))
	streamStatuses := make(map[string]map[string]string, len(unit.Config.Streams))

	// worstReceiverState tracks the worst top-level receiver state for streams without per-stream attributes
	var worstReceiverState client.UnitState
	var worstReceiverMessage string

	for _, stream := range unit.Config.Streams {
		var rs *status.AggregateStatus
		if receiverByInputID != nil {
			// Each stream has its own dedicated receiver
			rs = receiverByInputID[stream.Id]
		}

		if rs != nil {
			// Extract the stream's status from its receiver's attributes
			streamStatus := getStreamStatusFromReceiver(rs, stream.Id)
			if streamStatus != nil {
				unitStreamStatuses[stream.Id] = streamStatus
				streamStatusEvent := streamStatusToStatusEvent(streamStatus)
				isError := streamStatusEvent.Err() != nil
				streamState, streamMsg := StateWithMessage(streamStatusEvent)
				if !isError {
					streamMsg = ""
				}
				streamStatuses[stream.Id] = map[string]string{
					"error":  streamMsg,
					"status": streamState.String(),
				}
			} else {
				// No per-stream attributes, use the receiver's top-level status
				topState, topMsg := StateWithMessage(rs)
				if topState > worstReceiverState {
					worstReceiverState = topState
					worstReceiverMessage = topMsg
				}
				isError := rs.Err() != nil
				if !isError {
					topMsg = ""
				}
				streamStatuses[stream.Id] = map[string]string{
					"error":  topMsg,
					"status": topState.String(),
				}
			}
		} else if otelUnitStatus != nil {
			// No per-stream receiver, fall back to the single unit status (starting state)
			topState, topMsg := StateWithMessage(otelUnitStatus)
			isError := otelUnitStatus.Err() != nil
			if !isError {
				topMsg = ""
			}
			streamStatuses[stream.Id] = map[string]string{
				"error":  topMsg,
				"status": topState.String(),
			}
		}
	}

	var payload map[string]any
	if len(streamStatuses) > 0 {
		payload = map[string]any{
			"streams": streamStatuses,
		}
	}

	// Filestream without streams case: look up receiver by beat input ID
	if len(unit.Config.Streams) == 0 && receiverByInputID != nil {
		beatInputID := comp.GetBeatInputIDForUnit(unit.ID)
		if beatInputID != "" {
			if rs, ok := receiverByInputID[beatInputID]; ok {
				streamStatus := getStreamStatusFromReceiver(rs, beatInputID)
				if streamStatus != nil {
					unitState, unitMessage := StateWithMessage(streamStatusToStatusEvent(streamStatus))
					return runtime.ComponentUnitState{
						State:   unitState,
						Message: unitMessage,
						Payload: payload,
					}
				}
				topState, topMsg := StateWithMessage(rs)
				return runtime.ComponentUnitState{
					State:   topState,
					Message: topMsg,
					Payload: payload,
				}
			}
		}
	}

	// Compute unit state from per-stream attribute statuses if available
	if len(unitStreamStatuses) > 0 {
		unitState, unitMessage := unitStateFromStreamStatuses(unitStreamStatuses)
		// Also consider worst receiver top-level state for streams without attributes
		if worstReceiverState > unitState {
			unitState = worstReceiverState
			unitMessage = worstReceiverMessage
		}
		return runtime.ComponentUnitState{
			State:   unitState,
			Message: unitMessage,
			Payload: payload,
		}
	}

	// No per-stream attributes available; use worst receiver top-level state
	if worstReceiverState > 0 {
		return runtime.ComponentUnitState{
			State:   worstReceiverState,
			Message: worstReceiverMessage,
			Payload: payload,
		}
	}

	// Fall back to single unit status (starting state or no receivers)
	if otelUnitStatus != nil {
		topLevelState, topLevelMessage := StateWithMessage(otelUnitStatus)
		return runtime.ComponentUnitState{
			State:   topLevelState,
			Message: topLevelMessage,
			Payload: payload,
		}
	}

	return runtime.ComponentUnitState{
		Payload: payload,
	}
}

// unitStateFromStreamStatuses computes the unit state based on the stream statuses.
// This is a copy of the logic in https://github.com/elastic/beats/blob/main/x-pack/libbeat/common/otelbeat/status/reporter.go
func unitStateFromStreamStatuses(streamStatuses map[string]*serializablestatus.SerializableEvent) (unitState client.UnitState, unitMessage string) {
	reportedState := client.UnitStateHealthy
	reportedMsg := ""

	for _, s := range streamStatuses {
		state, message := StateWithMessage(streamStatusToStatusEvent(s))
		switch state {
		case client.UnitStateDegraded:
			if reportedState != client.UnitStateDegraded {
				reportedState = client.UnitStateDegraded
				reportedMsg = message
			}
		case client.UnitStateFailed:
			// we've encountered a failed stream.
			// short-circuit and return, as Failed state takes precedence over other states
			return state, message
		default:
		}
	}
	return reportedState, reportedMsg
}

func streamStatusToStatusEvent(streamStatus *serializablestatus.SerializableEvent) status.Event {
	// the below translation can't fail here, because stream statuses cannot have attributes
	streamStatusEvent, _ := serializablestatus.FromSerializableEvent(streamStatus)
	return streamStatusEvent
}

// ParseEntityStatusId parses an entity status ID into its kind and entity ID. An entity can be a pipeline or otel component.
// The ID is expected to be in the format "kind:entityId", where kind is either "pipeline" or the otel component type (e.g., "receiver", "exporter").
// The returned entityId may be empty - this is true for the top-level "extensions" key.
// This format is used by the healthcheckv2 extension.
func ParseEntityStatusId(id string) (kind string, entityId string, err error) {
	if id == "extensions" {
		return "extensions", "", nil
	}
	parts := strings.SplitN(id, ":", 2)
	if len(parts) != 2 {
		return "", "", fmt.Errorf("couldn't parse otel status id: %s", id)
	}
	return parts[0], parts[1], nil
}

// deepCopyStatus makes a deep copy of the status.
func deepCopyStatus(otelStatus *status.AggregateStatus) *status.AggregateStatus {
	if otelStatus == nil {
		return nil
	}

	newStatus := &status.AggregateStatus{
		Event: otelStatus.Event,
	}
	if otelStatus.ComponentStatusMap == nil {
		return newStatus
	}

	newStatus.ComponentStatusMap = make(map[string]*status.AggregateStatus, len(otelStatus.ComponentStatusMap))
	for k, v := range otelStatus.ComponentStatusMap {
		newStatus.ComponentStatusMap[k] = deepCopyStatus(v)
	}

	return newStatus
}
