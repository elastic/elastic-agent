// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package otelhelpers

import (
	"fmt"

	"github.com/open-telemetry/opentelemetry-collector-contrib/pkg/status"
	"go.opentelemetry.io/collector/component/componentstatus"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"
)

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
func StateWithMessage(current *status.AggregateStatus) (client.UnitState, string) {
	s := current.Status()
	switch s {
	case componentstatus.StatusNone:
		// didn't report a status, we assume with no status
		// that it is healthy
		return client.UnitStateHealthy, "Healthy"
	case componentstatus.StatusStarting:
		return client.UnitStateStarting, "Starting"
	case componentstatus.StatusOK:
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
