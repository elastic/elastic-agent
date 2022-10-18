// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package status

import (
	"encoding/json"
	"net/http"
	"time"
)

// LivenessResponse is the response body for the liveness endpoint.
type LivenessResponse struct {
	ID         string    `json:"id"`
	Status     string    `json:"status"`
	Message    string    `json:"message"`
	UpdateTime time.Time `json:"update_timestamp"`
}

// ServeHTTP is an HTTP Handler for the status controller.
// It uses the local agent status so it is able to report a degraded state if the fleet-server checkin has issues.
// Respose code is 200 for a healthy agent, and 503 otherwise.
// Response body is a JSON object that contains the agent ID, status, message, and the last status update time.
func (r *controller) ServeHTTP(wr http.ResponseWriter, req *http.Request) {
	s := r.LocalStatus()
	lr := LivenessResponse{
		ID:         r.agentID,
		Status:     s.Status.String(),
		Message:    s.Message,
		UpdateTime: s.UpdateTime,
	}
	status := http.StatusOK
	if s.Status != Healthy {
		status = http.StatusServiceUnavailable
	}

	wr.Header().Set("Content-Type", "application/json")
	wr.WriteHeader(status)
	enc := json.NewEncoder(wr)
	if err := enc.Encode(lr); err != nil {
		r.log.Errorf("Unable to encode liveness response: %v", err)
	}
}
