// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package monitoring

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/gorilla/mux"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/coordinator"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
)

const processIDKey = "processID"

func processHandler(coord *coordinator.Coordinator, statsHandler func(http.ResponseWriter, *http.Request) error) func(http.ResponseWriter, *http.Request) error {
	return func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")

		vars := mux.Vars(r)
		id, found := vars[processIDKey]

		if !found {
			return errorfWithStatus(http.StatusNotFound, "productID not found")
		}

		if id == "" || id == paths.BinaryName {
			// proxy stats for elastic agent process
			return statsHandler(w, r)
		}

		state := coord.State(false)

		for _, c := range state.Components {
			if matchesCloudProcessID(&c.Component, id) {
				data := struct {
					State   string `json:"state"`
					Message string `json:"message"`
				}{
					State:   c.State.State.String(),
					Message: c.State.Message,
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

		return errorWithStatus(http.StatusNotFound, fmt.Errorf("matching component %v not found", id))
	}
}
