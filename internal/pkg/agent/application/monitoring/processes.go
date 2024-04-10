// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package monitoring

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"
)

type source struct {
	Kind    string   `json:"kind"`
	Outputs []string `json:"outputs"`
}

type process struct {
	ID     string `json:"id"`
	PID    string `json:"pid,omitempty"`
	Binary string `json:"binary"`
	Source source `json:"source"`
}

func sourceFromComponentID(procID string) source {
	var s source
	var out string
	if pos := strings.LastIndex(procID, "-"); pos != -1 {
		out = procID[pos+1:]
	}
	if strings.HasSuffix(out, "monitoring") {
		s.Kind = "internal"
	} else {
		s.Kind = "configured"
	}
	s.Outputs = []string{out}
	return s
}

func processesHandler(coord CoordinatorState, livenessMode bool) func(http.ResponseWriter, *http.Request) error {
	return func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")

		procs := make([]process, 0)

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
			if comp.Component.InputSpec != nil {
				procs = append(procs, process{
					ID:     expectedCloudProcessID(comp.Component.InputSpec.BinaryName, comp.Component.ID),
					PID:    comp.LegacyPID,
					Binary: comp.Component.InputSpec.BinaryName,
					Source: sourceFromComponentID(comp.Component.ID),
				})
			}
		}
		data := struct {
			Processes          []process `json:"processes"`
			CoordinatorHealthy bool      `json:"coordinator_healthy"`
		}{
			Processes:          procs,
			CoordinatorHealthy: isUp,
		}

		bytes, err := json.Marshal(data)
		var content string
		if err != nil {
			content = fmt.Sprintf("Not valid json: %v", err)
		} else {
			content = string(bytes)
		}
		if livenessMode && (unhealthyComponent || !isUp) {
			w.WriteHeader(http.StatusInternalServerError)
		}
		fmt.Fprint(w, content)

		return nil
	}
}
