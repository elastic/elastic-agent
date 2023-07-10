// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package coordinator

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/elastic/elastic-agent/pkg/control/v2/client"
)

// LivenessResponse is the response body for the liveness endpoint.
type LivenessResponse struct {
	ID         string    `json:"id"`
	Status     string    `json:"status"`
	Message    string    `json:"message"`
	UpdateTime time.Time `json:"update_timestamp"`
}

// ServeHTTP is an HTTP Handler for the coordinatorr.
// Response code is 200 for a healthy agent, and 503 otherwise.
// Response body is a JSON object that contains the agent ID, status, message, and the last status update time.
func (c *Coordinator) ServeHTTP(wr http.ResponseWriter, req *http.Request) {
	s := c.State()
	lr := LivenessResponse{
		ID:      c.agentInfo.AgentID(),
		Status:  s.State.String(),
		Message: s.Message,

		// TODO(blakerouse): Coordinator should be changed to store the last timestamp that the state has changed.
		UpdateTime: time.Now().UTC(),
	}
	status := http.StatusOK
	if s.State != client.Healthy {
		status = http.StatusServiceUnavailable
	}

	wr.Header().Set("Content-Type", "application/json")
	wr.WriteHeader(status)
	enc := json.NewEncoder(wr)
	if err := enc.Encode(lr); err != nil {
		c.logger.Errorf("Unable to encode liveness response: %v", err)
	}
}
