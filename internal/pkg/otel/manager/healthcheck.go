// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package manager

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"go.opentelemetry.io/collector/confmap"

	"github.com/open-telemetry/opentelemetry-collector-contrib/pkg/status"
	"go.opentelemetry.io/collector/component/componentstatus"
)

const (
	// healthcheckv2 extension configuration settings
	// https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/extension/healthcheckv2extension
	healthCheckExtensionName            = "healthcheckv2"
	healthCheckIncludePermanentErrors   = true
	healthCheckIncludeRecoverableErrors = true
	healthCheckRecoveryDuration         = "5m"
	healthCheckHealthStatusPath         = "/health/status"
	healthCheckHealthStatusEnabled      = true
	healthCheckHealthConfigPath         = "/health/config"
	healthCheckHealthConfigEnabled      = false
)

// SerializableStatus is exported for json.Unmarshal
type SerializableStatus struct {
	StartTimestamp *time.Time `json:"start_time,omitempty"`
	*SerializableEvent
	ComponentStatuses map[string]*SerializableStatus `json:"components,omitempty"`
}

// SerializableEvent is exported for json.Unmarshal
type SerializableEvent struct {
	Healthy      bool      `json:"healthy"`
	StatusString string    `json:"status"`
	Error        string    `json:"error,omitempty"`
	Timestamp    time.Time `json:"status_time"`
}

// stringToStatusMap is a map from string representation of status to componentstatus.Status.
var stringToStatusMap = map[string]componentstatus.Status{
	"StatusNone":             componentstatus.StatusNone,
	"StatusStarting":         componentstatus.StatusStarting,
	"StatusOK":               componentstatus.StatusOK,
	"StatusRecoverableError": componentstatus.StatusRecoverableError,
	"StatusPermanentError":   componentstatus.StatusPermanentError,
	"StatusFatalError":       componentstatus.StatusFatalError,
	"StatusStopping":         componentstatus.StatusStopping,
	"StatusStopped":          componentstatus.StatusStopped,
}

// healthCheckEvent implements status.Event interface for health check events.
type healthCheckEvent struct {
	status    componentstatus.Status
	timestamp time.Time
	err       error
}

func (e *healthCheckEvent) Status() componentstatus.Status { return e.status }
func (e *healthCheckEvent) Timestamp() time.Time           { return e.timestamp }
func (e *healthCheckEvent) Err() error                     { return e.err }

// AllComponentsStatuses retrieves the status of all components from the health check endpoint.
func AllComponentsStatuses(ctx context.Context, httpHealthCheckPort int) (*status.AggregateStatus, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("http://localhost:%d/%s?verbose",
		httpHealthCheckPort, healthCheckHealthStatusPath), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create http request: %w", err)
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get status: %w", err)
	}
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read body: %w", err)
	}

	serStatus := &SerializableStatus{}
	err = json.Unmarshal(body, serStatus)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal serializable status: %w", err)
	}

	return fromSerializableStatus(serStatus), nil
}

// fromSerializableStatus reconstructs an AggregateStatus from serializableStatus.
func fromSerializableStatus(ss *SerializableStatus) *status.AggregateStatus {
	ev := fromSerializableEvent(ss.SerializableEvent)

	as := &status.AggregateStatus{
		Event:              ev,
		ComponentStatusMap: make(map[string]*status.AggregateStatus),
	}

	for k, cs := range ss.ComponentStatuses {
		as.ComponentStatusMap[k] = fromSerializableStatus(cs)
	}

	return as
}

// fromSerializableEvent reconstructs a status.Event from SerializableEvent.
func fromSerializableEvent(se *SerializableEvent) status.Event {
	if se == nil {
		return nil
	}

	var err error
	if se.Error != "" {
		err = errors.New(se.Error)
	}

	statusVal, ok := stringToStatusMap[se.StatusString]
	if !ok {
		statusVal = componentstatus.StatusNone
	}

	return &healthCheckEvent{
		status:    statusVal,
		timestamp: se.Timestamp,
		err:       err,
	}
}

// compareStatuses checks if two AggregateStatuses are equal, excluding timestamp.
func compareStatuses(s1, s2 *status.AggregateStatus) bool {
	if s1 == nil && s2 == nil {
		// both nil
		return true
	}
	if s1 == nil || s2 == nil {
		// one of them is nil
		return false
	}
	if s1.Status() != s2.Status() {
		// status doesn't match
		return false
	}

	// NOTE: we don't check the timestamp
	// as we care only about the event and component statuses/error differences

	if (s1.Err() == nil && s2.Err() != nil) || (s1.Err() != nil && s2.Err() == nil) {
		return false
	}
	if s1.Err() != nil && s2.Err() != nil {
		if s1.Err().Error() != s2.Err().Error() {
			return false
		}
	}

	if len(s1.ComponentStatusMap) != len(s2.ComponentStatusMap) {
		return false
	}
	for k, v1 := range s1.ComponentStatusMap {
		v2, ok := s2.ComponentStatusMap[k]
		if !ok {
			return false
		}
		if !compareStatuses(v1, v2) {
			return false
		}
	}
	return true
}

// aggregateStatus creates a new AggregateStatus with the provided component status and error.
func aggregateStatus(sts componentstatus.Status, err error) *status.AggregateStatus {
	return &status.AggregateStatus{
		Event: &healthCheckEvent{
			status:    sts,
			timestamp: time.Now(),
			err:       err,
		},
		ComponentStatusMap: make(map[string]*status.AggregateStatus),
	}
}

// injectHealthCheckV2Extension injects the healthcheckv2 extension into the provided configuration.
func injectHealthCheckV2Extension(conf *confmap.Conf, healthCheckExtensionID string, httpHealthCheckPort int) error {
	err := conf.Merge(confmap.NewFromStringMap(map[string]interface{}{
		"extensions": map[string]interface{}{
			healthCheckExtensionID: map[string]interface{}{
				"use_v2": true,
				"component_health": map[string]interface{}{
					"include_permanent_errors":   healthCheckIncludePermanentErrors,
					"include_recoverable_errors": healthCheckIncludeRecoverableErrors,
					"recovery_duration":          healthCheckRecoveryDuration,
				},
				"http": map[string]interface{}{
					"endpoint": fmt.Sprintf("localhost:%d", httpHealthCheckPort),
					"status": map[string]interface{}{
						"enabled": healthCheckHealthStatusEnabled,
						"path":    healthCheckHealthStatusPath,
					},
					"config": map[string]interface{}{
						"enabled": healthCheckHealthConfigEnabled,
						"path":    healthCheckHealthConfigPath,
					},
				},
			},
		},
	}))
	if err != nil {
		return fmt.Errorf("merge into extensions failed: %w", err)
	}
	serviceConf, err := conf.Sub("service")
	if err != nil {
		//nolint:nilerr // ignore the error, no service defined in the configuration
		// this is going to error by the collector any way no reason to pollute with more
		// error information that is not really related to the issue at the moment
		return nil
	}
	extensionsRaw := serviceConf.Get("extensions")
	if extensionsRaw == nil {
		// no extensions defined on service (easily add it)
		err = conf.Merge(confmap.NewFromStringMap(map[string]interface{}{
			"service": map[string]interface{}{
				"extensions": []interface{}{healthCheckExtensionID},
			},
		}))
		if err != nil {
			return fmt.Errorf("merge into service::extensions failed: %w", err)
		}
		return nil
	}
	extensionsSlice, ok := extensionsRaw.([]interface{})
	if !ok {
		return fmt.Errorf("merge into service::extensions failed: expected []interface{}, got %T", extensionsRaw)
	}
	for _, extensionRaw := range extensionsSlice {
		extension, ok := extensionRaw.(string)
		if ok && extension == healthCheckExtensionID {
			// already present, nothing to do
			return nil
		}
	}
	extensionsSlice = append(extensionsSlice, healthCheckExtensionID)
	err = conf.Merge(confmap.NewFromStringMap(map[string]interface{}{
		"service": map[string]interface{}{
			"extensions": extensionsSlice,
		},
	}))
	if err != nil {
		return fmt.Errorf("merge into service::extensions failed: %w", err)
	}
	return nil
}
