// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package monitoring

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/coordinator"
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

func processesHandler(coord *coordinator.Coordinator) func(http.ResponseWriter, *http.Request) error {
	return func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")

		procs := make([]process, 0)

		state := coord.State()

		for _, c := range state.Components {
			if c.Component.InputSpec != nil {
				procs = append(procs, process{
					ID:     expectedCloudProcessID(&c.Component),
					PID:    c.LegacyPID,
					Binary: c.Component.InputSpec.BinaryName,
					Source: sourceFromComponentID(c.Component.ID),
				})
			}
		}
		data := struct {
			Processes []process `json:"processes"`
		}{
			Processes: procs,
		}

		bytes, err := json.Marshal(data)
		var content string
		if err != nil {
			content = fmt.Sprintf("Not valid json: %v", err)
		} else {
			content = string(bytes)
		}
		fmt.Fprint(w, content)

		return nil
	}
}
