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

const formValueKey = "failon"

type LivenessFailConfig struct {
	Degraded    bool `yaml:"degraded" config:"degraded"`
	Failed      bool `yaml:"failed" config:"failed"`
	Coordinator bool `yaml:"coordinator" config:"coordinator"`
}

// process the form values we get via HTTP
func handleFormValues(req *http.Request) (LivenessFailConfig, error) {
	err := req.ParseForm()
	if err != nil {
		return LivenessFailConfig{}, fmt.Errorf("Error parsing form: %w", err)
	}

	defaultUserCfg := LivenessFailConfig{Degraded: false, Failed: true, Coordinator: true}

	for formKey := range req.Form {
		if formKey != formValueKey {
			return defaultUserCfg, fmt.Errorf("got invalid HTTP form key: '%s'", formKey)
		}
	}

	userConfig := req.Form.Get(formValueKey)
	switch userConfig {
	case "failed", "":
		return defaultUserCfg, nil
	case "degraded":
		return LivenessFailConfig{Failed: true, Degraded: true, Coordinator: true}, nil
	case "coordinator":
		return LivenessFailConfig{Failed: false, Degraded: false, Coordinator: true}, nil
	default:
		return defaultUserCfg, fmt.Errorf("got unexpected value for `%s` attribute: %s", formValueKey, userConfig)
	}
}

func livenessHandler(coord CoordinatorState) func(http.ResponseWriter, *http.Request) error {
	return func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")

		state := coord.State()
		isUp := coord.CoordinatorActive(time.Second * 10)

		failConfig, err := handleFormValues(r)
		if err != nil {
			return fmt.Errorf("error handling form values: %w", err)
		}

		// if user has requested `coordinator` mode, just revert to that, skip everything else
		if !failConfig.Degraded && !failConfig.Failed && failConfig.Coordinator {
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
		// bias towards the coordinator check, since it can be otherwise harder to diagnose
		if !isUp {
			w.WriteHeader(http.StatusServiceUnavailable)
		} else if unhealthyComponent {
			w.WriteHeader(http.StatusInternalServerError)
		}
		return nil
	}
}
