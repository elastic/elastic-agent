// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package fleetapi

import "encoding/json"

// AckEvent is an event sent in an ACK request.
type AckEvent struct {
	EventType string          `json:"type"`              //  'STATE' | 'ERROR' | 'ACTION_RESULT' | 'ACTION'
	SubType   string          `json:"subtype"`           // 'RUNNING','STARTING','IN_PROGRESS','CONFIG','FAILED','STOPPING','STOPPED','DATA_DUMP','ACKNOWLEDGED','UNKNOWN';
	Timestamp string          `json:"timestamp"`         // : '2019-01-05T14:32:03.36764-05:00'
	ActionID  string          `json:"action_id"`         // : '48cebde1-c906-4893-b89f-595d943b72a2',
	AgentID   string          `json:"agent_id"`          // : 'agent1',
	Message   string          `json:"message,omitempty"` // : 'hello2',
	Payload   json.RawMessage `json:"payload,omitempty"` // : 'payload2',
	Data      json.RawMessage `json:"data,omitempty"`    // : 'data',

	ActionInputType string                 `json:"action_input_type,omitempty"` // copy of original action input_type
	ActionData      json.RawMessage        `json:"action_data,omitempty"`       // copy of original action data
	ActionResponse  map[string]interface{} `json:"action_response,omitempty"`   // custom (per beat) response payload
	StartedAt       string                 `json:"started_at,omitempty"`        // time action started
	CompletedAt     string                 `json:"completed_at,omitempty"`      // time action completed
	Error           string                 `json:"error,omitempty"`             // optional action error
}

// AckRequest consists of multiple actions acked to fleet ui.
// POST /agents/{agentId}/acks
// Authorization: ApiKey {AgentAccessApiKey}
//
//	{
//	  "action_ids": ["id1"]
//	}
type AckRequest struct {
	Events []AckEvent `json:"events"`
}

// Validate validates the ack request before sending it to the API.
func (e *AckRequest) Validate() error {
	return nil
}

// AckResponseItem the status items for individual acks
type AckResponseItem struct {
	Status  int    `json:"status"`
	Message string `json:"message,omitempty"`
}

// AckResponse is the response send back from the server.
// 200
//
//	{
//		 "action": "acks"
//	  "items": [
//		    {"status": 200},
//		    {"status": 404},
//	  ]
//	}
type AckResponse struct {
	Action string            `json:"action"`
	Errors bool              `json:"errors,omitempty"` // indicates that some of the events in the ack request failed
	Items  []AckResponseItem `json:"items,omitempty"`
}

// Validate validates the response send from the server.
func (e *AckResponse) Validate() error {
	return nil
}
