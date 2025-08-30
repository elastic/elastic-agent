// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package monitoring

import (
	"net/http"
	"time"
)

// readinessHandler returns an HTTP handler function that checks the readiness of the service.
// If a CoordinatorState is provided, it checks if the coordinator is active within a 10-second timeout.
//
// This is meant to be a very simple check, just ensure that the service is up and running. For more detail
// about the liveness of the service use the livenessHandler.
func readinessHandler(coord CoordinatorState) func(http.ResponseWriter, *http.Request) error {
	return func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")

		if coord != nil {
			// to be ready the coordinator must be active
			if !coord.IsActive(time.Second * 10) {
				w.WriteHeader(http.StatusServiceUnavailable)
				return nil
			}
		}

		w.WriteHeader(http.StatusOK)
		return nil
	}
}
