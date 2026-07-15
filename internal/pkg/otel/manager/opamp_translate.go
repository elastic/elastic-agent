// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package manager

import (
	"errors"
	"time"

	"github.com/open-telemetry/opamp-go/protobufs"
	"github.com/open-telemetry/opentelemetry-collector-contrib/pkg/status"
	"go.opentelemetry.io/collector/component/componentstatus"
	"go.opentelemetry.io/collector/pdata/pcommon"
)

// opampStatusStringToStatus maps the string form produced by
// componentstatus.Status.String() (e.g. "StatusOK") back to the enum.
// opampextension reports protobufs.ComponentHealth.Status using this form.
var opampStatusStringToStatus = map[string]componentstatus.Status{
	"StatusNone":             componentstatus.StatusNone,
	"StatusStarting":         componentstatus.StatusStarting,
	"StatusOK":               componentstatus.StatusOK,
	"StatusRecoverableError": componentstatus.StatusRecoverableError,
	"StatusPermanentError":   componentstatus.StatusPermanentError,
	"StatusFatalError":       componentstatus.StatusFatalError,
	"StatusStopping":         componentstatus.StatusStopping,
	"StatusStopped":          componentstatus.StatusStopped,
}

// componentHealthEvent implements status.Event for an opamp Health entry.
// Attributes are always empty: protobufs.ComponentHealth has no attributes
// field and opampextension does not propagate the source pcommon.Map.
type componentHealthEvent struct {
	status     componentstatus.Status
	timestamp  time.Time
	err        error
	attributes pcommon.Map
}

func (e *componentHealthEvent) Status() componentstatus.Status { return e.status }
func (e *componentHealthEvent) Timestamp() time.Time           { return e.timestamp }
func (e *componentHealthEvent) Err() error                     { return e.err }
func (e *componentHealthEvent) Attributes() pcommon.Map        { return e.attributes }

// componentHealthToAggregate converts a protobufs.ComponentHealth tree into
// an *status.AggregateStatus equivalent to what healthcheckv2 would produce.
func componentHealthToAggregate(h *protobufs.ComponentHealth) *status.AggregateStatus {
	if h == nil {
		return nil
	}

	statusVal, ok := opampStatusStringToStatus[h.Status]
	if !ok {
		statusVal = componentstatus.StatusNone
	}

	var err error
	if h.LastError != "" {
		err = errors.New(h.LastError)
	}

	// StatusTimeUnixNano fits in int64 for any timestamp before year 2262;
	// the conversion is safe for the lifetime of the universe we operate in.
	//nolint:gosec // G115: see comment above.
	timestamp := time.Unix(0, int64(h.StatusTimeUnixNano))
	ev := &componentHealthEvent{
		status:     statusVal,
		timestamp:  timestamp,
		err:        err,
		attributes: pcommon.NewMap(),
	}

	agg := &status.AggregateStatus{
		Event:              ev,
		ComponentStatusMap: make(map[string]*status.AggregateStatus, len(h.ComponentHealthMap)),
	}
	for k, child := range h.ComponentHealthMap {
		agg.ComponentStatusMap[k] = componentHealthToAggregate(child)
	}
	return agg
}
