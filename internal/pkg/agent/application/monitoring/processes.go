// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package monitoring

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
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

func processesHandler(coord CoordinatorState) func(http.ResponseWriter, *http.Request) error {
	return func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")

		procs := make([]process, 0)

		state := coord.State()

		for iter, c := range state.Components {
			if c.Component.InputSpec != nil {
				procs = append(procs, process{
					// access the components array manually to avoid a memory aliasing error. This is fixed in go 1.22
					ID:     expectedCloudProcessID(&state.Components[iter].Component),
					PID:    c.LegacyPID,
					Binary: c.Component.BinaryName(),
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
