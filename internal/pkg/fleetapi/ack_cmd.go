// Licensed to Elasticsearch B.V. under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Elasticsearch B.V. licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package fleetapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi/client"
)

const ackPath = "/api/fleet/agents/%s/acks"

// AckEvent is an event sent in an ACK request.
type AckEvent struct {
	EventType string `json:"type"`              //  'STATE' | 'ERROR' | 'ACTION_RESULT' | 'ACTION'
	SubType   string `json:"subtype"`           // 'RUNNING','STARTING','IN_PROGRESS','CONFIG','FAILED','STOPPING','STOPPED','DATA_DUMP','ACKNOWLEDGED','UNKNOWN';
	Timestamp string `json:"timestamp"`         // : '2019-01-05T14:32:03.36764-05:00',
	ActionID  string `json:"action_id"`         // : '48cebde1-c906-4893-b89f-595d943b72a2',
	AgentID   string `json:"agent_id"`          // : 'agent1',
	Message   string `json:"message,omitempty"` // : 'hello2',
	Payload   string `json:"payload,omitempty"` // : 'payload2',

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
// {
//   "action_ids": ["id1"]
// }
type AckRequest struct {
	Events []AckEvent `json:"events"`
}

// Validate validates the enrollment request before sending it to the API.
func (e *AckRequest) Validate() error {
	return nil
}

// AckResponse is the response send back from the server.
// 200
// {
// 	 "action": "acks"
// }
type AckResponse struct {
	Action string `json:"action"`
}

// Validate validates the response send from the server.
func (e *AckResponse) Validate() error {
	return nil
}

// AckCmd is a fleet API command.
type AckCmd struct {
	client client.Sender
	info   agentInfo
}

// NewAckCmd creates a new api command.
func NewAckCmd(info agentInfo, client client.Sender) *AckCmd {
	return &AckCmd{
		client: client,
		info:   info,
	}
}

// Execute ACK of actions to the Fleet.
func (e *AckCmd) Execute(ctx context.Context, r *AckRequest) (*AckResponse, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}

	b, err := json.Marshal(r)
	if err != nil {
		return nil, errors.New(err,
			"fail to encode the ack request",
			errors.TypeUnexpected)
	}

	ap := fmt.Sprintf(ackPath, e.info.AgentID())
	resp, err := e.client.Send(ctx, "POST", ap, nil, nil, bytes.NewBuffer(b))
	if err != nil {
		return nil, errors.New(err,
			"fail to ack to fleet",
			errors.TypeNetwork,
			errors.M(errors.MetaKeyURI, ap))
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, client.ExtractError(resp.Body)
	}

	ackResponse := &AckResponse{}
	decoder := json.NewDecoder(resp.Body)
	if err := decoder.Decode(ackResponse); err != nil {
		return nil, errors.New(err,
			"fail to decode ack response",
			errors.TypeNetwork,
			errors.M(errors.MetaKeyURI, ap))
	}

	if err := ackResponse.Validate(); err != nil {
		return nil, err
	}

	return ackResponse, nil
}
