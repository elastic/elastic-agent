// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package status

import (
	"errors"
	"fmt"
	"time"

	"go.opentelemetry.io/collector/pdata/pcommon"

	"github.com/open-telemetry/opentelemetry-collector-contrib/pkg/status"
	"go.opentelemetry.io/collector/component/componentstatus"
)

// SerializableStatus is exported for json.Unmarshal
type SerializableStatus struct {
	StartTimestamp *time.Time `json:"start_time,omitempty"`
	*SerializableEvent
	ComponentStatuses map[string]*SerializableStatus `json:"components,omitempty"`
}

// SerializableEvent is exported for json.Unmarshal
type SerializableEvent struct {
	Healthy      bool           `json:"healthy"`
	StatusString string         `json:"status" mapstructure:"status"`
	Error        string         `json:"error,omitempty"`
	Timestamp    time.Time      `json:"status_time"`
	Attributes   map[string]any `json:"attributes"`
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
	status     componentstatus.Status
	timestamp  time.Time
	err        error
	attributes pcommon.Map
}

func (e *healthCheckEvent) Status() componentstatus.Status { return e.status }
func (e *healthCheckEvent) Timestamp() time.Time           { return e.timestamp }
func (e *healthCheckEvent) Err() error                     { return e.err }
func (e *healthCheckEvent) Attributes() pcommon.Map        { return e.attributes }

// FromSerializableStatus reconstructs an AggregateStatus from serializableStatus.
func FromSerializableStatus(ss *SerializableStatus) (*status.AggregateStatus, error) {
	ev, err := FromSerializableEvent(ss.SerializableEvent)
	if err != nil {
		return nil, err
	}

	as := &status.AggregateStatus{
		Event:              ev,
		ComponentStatusMap: make(map[string]*status.AggregateStatus),
	}

	for k, cs := range ss.ComponentStatuses {
		componentStatus, componentErr := FromSerializableStatus(cs)
		if componentErr != nil {
			return nil, fmt.Errorf("failed to deserialize component status %s: %w", k, componentErr)
		}
		as.ComponentStatusMap[k] = componentStatus
	}

	return as, nil
}

// FromSerializableEvent reconstructs a status.Event from SerializableEvent.
func FromSerializableEvent(se *SerializableEvent) (status.Event, error) {
	if se == nil {
		return nil, nil
	}

	var err error
	if se.Error != "" {
		err = errors.New(se.Error)
	}

	statusVal, ok := stringToStatusMap[se.StatusString]
	if !ok {
		statusVal = componentstatus.StatusNone
	}

	attributes := pcommon.NewMap()
	parseErr := attributes.FromRaw(se.Attributes)
	if parseErr != nil {
		return nil, fmt.Errorf("error parsing event attributes %v: %w", se.Attributes, parseErr)
	}
	return &healthCheckEvent{
		status:     statusVal,
		timestamp:  se.Timestamp,
		err:        err,
		attributes: attributes,
	}, nil
}

// CompareStatuses checks if two AggregateStatuses are equal, excluding timestamp.
func CompareStatuses(s1, s2 *status.AggregateStatus) bool {
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

	if !s1.Attributes().Equal(s2.Attributes()) {
		return false
	}

	if len(s1.ComponentStatusMap) != len(s2.ComponentStatusMap) {
		return false
	}
	for k, v1 := range s1.ComponentStatusMap {
		v2, ok := s2.ComponentStatusMap[k]
		if !ok {
			return false
		}
		if !CompareStatuses(v1, v2) {
			return false
		}
	}
	return true
}

// AggregateStatus creates a new AggregateStatus with the provided component status and error.
func AggregateStatus(sts componentstatus.Status, err error) *status.AggregateStatus {
	return &status.AggregateStatus{
		Event: &healthCheckEvent{
			status:     sts,
			timestamp:  time.Now(),
			err:        err,
			attributes: pcommon.NewMap(),
		},
		ComponentStatusMap: make(map[string]*status.AggregateStatus),
	}
}
