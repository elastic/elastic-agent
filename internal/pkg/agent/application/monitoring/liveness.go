// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package monitoring

import (
	"fmt"
	"net/http"
	"time"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"
)

func livenessHandler(coord CoordinatorState) func(http.ResponseWriter, *http.Request) error {
	return func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")

		state := coord.State()
		isUp := coord.CoordinatorActive(time.Second * 10)

		failConfig, err := handleFormValues(r)
		if err != nil {
			return fmt.Errorf("error handling form values: %w", err)
		}

		unhealthyComponent := false
		for _, comp := range state.Components {
			if (failConfig.Failed && comp.State.State == client.UnitStateFailed) || (failConfig.Degraded && comp.State.State == client.UnitStateDegraded) {
				unhealthyComponent = true
			}
		}
		if !isUp {
			w.WriteHeader(http.StatusServiceUnavailable)
		} else if unhealthyComponent {
			w.WriteHeader(http.StatusInternalServerError)
		}
		return nil
	}
}
