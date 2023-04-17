// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package fleetapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi/client"
)

const checkingPath = "/api/fleet/agents/%s/checkin"

// CheckinUnit provides information about a unit during checkin.
type CheckinUnit struct {
	ID      string                 `json:"id"`
	Type    string                 `json:"type"`
	Status  string                 `json:"status"`
	Message string                 `json:"message"`
	Payload map[string]interface{} `json:"payload,omitempty"`
}

// CheckinShipperReference provides information about a component shipper connection during checkin.
type CheckinShipperReference struct {
	ComponentID string `json:"component_id"`
	UnitID      string `json:"unit_id"`
}

// CheckinComponent provides information about a component during checkin.
type CheckinComponent struct {
	ID      string                   `json:"id"`
	Type    string                   `json:"type"`
	Status  string                   `json:"status"`
	Message string                   `json:"message"`
	Units   []CheckinUnit            `json:"units,omitempty"`
	Shipper *CheckinShipperReference `json:"shipper,omitempty"`
}

// CheckinDuration is an alias for time.Duration used to control json marshaling/unmarshaling.
// We need this as we have to control the marshaling of poll_timeout into a string during
// the checkin request to fleet.
// Fleet accepts a duration string that can be parsed using the time.ParseDuration() function, so
// we need to marshal using the corresponding function time.Duration.String() instead of the
// default marshaling of the time.Duration type (it would marshaled as an integer since it's really an int64)
type CheckinDuration time.Duration

// MarshalJSON implements the json.Marshaler interface
func (jd CheckinDuration) MarshalJSON() ([]byte, error) {
	str := time.Duration(jd).String()
	return []byte(`"` + str + `"`), nil
}

// UnmarshalJSON implements the json.Unmarshaler interface
func (jd *CheckinDuration) UnmarshalJSON(b []byte) error {
	parsed, err := time.ParseDuration(string(b))
	if err != nil {
		return fmt.Errorf("parsing duration %q: %w", b, err)
	}

	*jd = CheckinDuration(parsed)
	return nil
}

// CheckinRequest consists of multiple events reported to fleet ui.
type CheckinRequest struct {
	Status      string             `json:"status"`
	AckToken    string             `json:"ack_token,omitempty"`
	Metadata    *info.ECSMeta      `json:"local_metadata,omitempty"`
	Message     string             `json:"message"`                // V2 Agent message
	Components  []CheckinComponent `json:"components"`             // V2 Agent components
	PollTimeout CheckinDuration    `json:"poll_timeout,omitempty"` // Fleet long polls: agent poll duration indicator
}

// SerializableEvent is a representation of the event to be send to the Fleet Server API via the checkin
// endpoint, we are liberal into what we accept to be send you only need a type and be able to be
// serialized into JSON.
type SerializableEvent interface {
	// Type return the type of the event, this must be included in the serialized document.
	Type() string

	// Timestamp is used to keep track when the event was created in the system.
	Timestamp() time.Time

	// Message is a human readable string to explain what the event does, this would be displayed in
	// the UI as a string of text.
	Message() string
}

// Validate validates the enrollment request before sending it to the API.
func (e *CheckinRequest) Validate() error {
	return nil
}

// CheckinResponse is the response send back from the server which contains all the action that
// need to be executed or proxy to running processes.
type CheckinResponse struct {
	AckToken string  `json:"ack_token"`
	Actions  Actions `json:"actions"`
}

// Validate validates the response send from the server.
func (e *CheckinResponse) Validate() error {
	return nil
}

// CheckinCmd is a fleet API command.
type CheckinCmd struct {
	client client.Sender
	info   agentInfo
}

type agentInfo interface {
	AgentID() string
}

// NewCheckinCmd creates a new api command.
func NewCheckinCmd(info agentInfo, client client.Sender) *CheckinCmd {
	return &CheckinCmd{
		client: client,
		info:   info,
	}
}

// Execute enroll the Agent in the Fleet Server. Returns the decoded check in response, a duration indicating
// how long the request took, and an error.
func (e *CheckinCmd) Execute(ctx context.Context, r *CheckinRequest) (*CheckinResponse, time.Duration, error) {
	if err := r.Validate(); err != nil {
		return nil, 0, err
	}

	b, err := json.Marshal(r)
	if err != nil {
		return nil, 0, errors.New(err,
			"fail to encode the checkin request",
			errors.TypeUnexpected)
	}

	cp := fmt.Sprintf(checkingPath, e.info.AgentID())
	sendStart := time.Now()
	resp, err := e.client.Send(ctx, "POST", cp, nil, nil, bytes.NewBuffer(b))
	sendDuration := time.Since(sendStart)
	if err != nil {
		return nil, sendDuration, errors.New(err,
			"fail to checkin to fleet-server",
			errors.TypeNetwork,
			errors.M(errors.MetaKeyURI, cp))
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, sendDuration, client.ExtractError(resp.Body)
	}

	rs, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, sendDuration, errors.New(err, "failed to read checkin response")
	}

	checkinResponse := &CheckinResponse{}
	decoder := json.NewDecoder(bytes.NewReader(rs))
	if err := decoder.Decode(checkinResponse); err != nil {
		return nil, sendDuration, errors.New(err,
			"fail to decode checkin response",
			errors.TypeNetwork,
			errors.M(errors.MetaKeyURI, cp))
	}

	if err := checkinResponse.Validate(); err != nil {
		return nil, sendDuration, err
	}

	return checkinResponse, sendDuration, nil
}
