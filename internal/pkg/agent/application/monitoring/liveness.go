// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package monitoring

import (
	"fmt"
	"net/http"
	"time"

	"go.opentelemetry.io/collector/component/componentstatus"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"

	"github.com/elastic/elastic-agent/internal/pkg/otel/otelhelpers"
)

const formValueKey = "failon"

type LivenessFailConfig struct {
	Degraded  bool `yaml:"degraded" config:"degraded"`
	Failed    bool `yaml:"failed" config:"failed"`
	Heartbeat bool `yaml:"heartbeat" config:"heartbeat"`
}

// process the form values we get via HTTP
func handleFormValues(req *http.Request) (LivenessFailConfig, error) {
	err := req.ParseForm()
	if err != nil {
		return LivenessFailConfig{}, fmt.Errorf("Error parsing form: %w", err)
	}

	defaultUserCfg := LivenessFailConfig{Degraded: false, Failed: false, Heartbeat: true}

	for formKey := range req.Form {
		if formKey != formValueKey {
			return defaultUserCfg, fmt.Errorf("got invalid HTTP form key: '%s'", formKey)
		}
	}

	userConfig := req.Form.Get(formValueKey)
	switch userConfig {
	case "failed":
		return LivenessFailConfig{Degraded: false, Failed: true, Heartbeat: true}, nil
	case "degraded":
		return LivenessFailConfig{Failed: true, Degraded: true, Heartbeat: true}, nil
	case "heartbeat", "":
		return defaultUserCfg, nil
	default:
		return defaultUserCfg, fmt.Errorf("got unexpected value for `%s` attribute: %s", formValueKey, userConfig)
	}
}

func livenessHandler(coord CoordinatorState) func(http.ResponseWriter, *http.Request) error {
	return func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")

		state := coord.State()
		isUp := coord.IsActive(time.Second * 10)
		// the coordinator check is always on, so if that fails, always return false
		if !isUp {
			w.WriteHeader(http.StatusServiceUnavailable)
			return nil
		}

		failConfig, err := handleFormValues(r)
		if err != nil {
			return fmt.Errorf("error handling form values: %w", err)
		}

		// if user has requested `coordinator` mode, just revert to that, skip everything else
		if !failConfig.Degraded && !failConfig.Failed && failConfig.Heartbeat {
			if !isUp {
				w.WriteHeader(http.StatusServiceUnavailable)
				return nil
			}
		}

		unhealthyComponent := false
		for _, comp := range state.Components {
			if (failConfig.Failed && comp.State.State == client.UnitStateFailed) || (failConfig.Degraded && comp.State.State == client.UnitStateDegraded) {
				unhealthyComponent = true
			}
		}
		if state.Collector != nil {
			if (failConfig.Failed && (otelhelpers.HasStatus(state.Collector, componentstatus.StatusFatalError) || otelhelpers.HasStatus(state.Collector, componentstatus.StatusPermanentError))) || (failConfig.Degraded && otelhelpers.HasStatus(state.Collector, componentstatus.StatusRecoverableError)) {
				unhealthyComponent = true
			}
		}
		// bias towards the coordinator check, since it can be otherwise harder to diagnose
		if unhealthyComponent {
			w.WriteHeader(http.StatusInternalServerError)
		}
		return nil
	}
}
