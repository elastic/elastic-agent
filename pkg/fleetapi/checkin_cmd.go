// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package fleetapi

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/elastic/elastic-agent/pkg/ecsmeta"
	"github.com/elastic/elastic-agent/pkg/upgrade/details"
)

// ErrInvalidAPIKey is returned when Fleet Server responds with 401 Unauthorized.
var ErrInvalidAPIKey = errors.New("invalid API key")

const checkingPath = "/api/fleet/agents/%s/checkin"
const checkinContentEncodingHeader = "Content-Encoding"
const checkinContentEncodingGzip = "gzip"

// Sender is the interface for sending HTTP requests to Fleet Server.
type Sender interface {
	Send(
		ctx context.Context,
		method string,
		path string,
		params url.Values,
		headers http.Header,
		body io.Reader,
	) (*http.Response, error)
}

// AgentInfo provides the agent's identity.
type AgentInfo interface {
	AgentID() string
}

// SerializableEvent is a representation of the event to be sent to the Fleet Server API via the checkin
// endpoint, we are liberal into what we accept to be sent you only need a type and be able to be
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

// CheckinUnit provides information about a unit during checkin.
type CheckinUnit struct {
	ID      string                 `json:"id"`
	Type    string                 `json:"type"`
	Status  string                 `json:"status"`
	Message string                 `json:"message"`
	Payload map[string]interface{} `json:"payload,omitempty"`
}

// CheckinComponent provides information about a component during checkin.
type CheckinComponent struct {
	ID      string        `json:"id"`
	Type    string        `json:"type"`
	Status  string        `json:"status"`
	Message string        `json:"message"`
	Units   []CheckinUnit `json:"units,omitempty"`
}

// CheckinRollback provides rollback information during checkin.
type CheckinRollback struct {
	Version    string    `json:"version"`
	ValidUntil time.Time `json:"valid_until"`
}

// CheckinUpgrade provides upgrade information during checkin.
type CheckinUpgrade struct {
	Rollbacks []CheckinRollback `json:"rollbacks,omitempty"`
}

// CheckinRequest consists of multiple events reported to fleet ui.
type CheckinRequest struct {
	Status            string             `json:"status"`
	AckToken          string             `json:"ack_token,omitempty"`
	Metadata          *ecsmeta.ECSMeta   `json:"local_metadata,omitempty"`
	Message           string             `json:"message"`    // V2 Agent message
	Components        []CheckinComponent `json:"components"` // V2 Agent components
	UpgradeDetails    *details.Details   `json:"upgrade_details,omitempty"`
	AgentPolicyID     string             `json:"agent_policy_id,omitempty"`
	PolicyRevisionIDX int64              `json:"policy_revision_idx,omitempty"`
	Upgrade           CheckinUpgrade     `json:"upgrade,omitempty"`
}

// Validate validates the enrollment request before sending it to the API.
func (e *CheckinRequest) Validate() error {
	return nil
}

// CheckinResponse is the response sent back from the server which contains all the actions that
// need to be executed or proxied to running processes.
// Actions is json.RawMessage so consumers can unmarshal into their own action types.
type CheckinResponse struct {
	AckToken     string          `json:"ack_token"`
	Actions      json.RawMessage `json:"actions"`
	FleetWarning string          `json:"-"`
}

// Validate validates the response sent from the server.
func (e *CheckinResponse) Validate() error {
	return nil
}

// CheckinCmd is a fleet API command.
type CheckinCmd struct {
	client      Sender
	info        AgentInfo
	compression string // "gzip" or "none"
}

// NewCheckinCmd creates a new api command.
// compression must be either "gzip" (compress request bodies) or "none" (no compression).
func NewCheckinCmd(info AgentInfo, client Sender, compression string) *CheckinCmd {
	return &CheckinCmd{
		client:      client,
		info:        info,
		compression: compression,
	}
}

// Execute checks in the Agent to the Fleet Server. Returns the decoded check in response, a duration indicating
// how long the request took, and an error.
func (e *CheckinCmd) Execute(ctx context.Context, r *CheckinRequest) (*CheckinResponse, time.Duration, error) {
	if err := r.Validate(); err != nil {
		return nil, 0, err
	}

	b, err := json.Marshal(r)
	if err != nil {
		return nil, 0, fmt.Errorf("fail to encode the checkin request: %w", err)
	}

	requestHeaders := http.Header{}
	requestBody := bytes.NewBuffer(b)
	if e.compression == "gzip" {
		requestBody, err = gzipEncodeCheckinRequestBody(b)
		if err != nil {
			return nil, 0, fmt.Errorf("fail to gzip encode checkin request: %w", err)
		}
		requestHeaders.Set(checkinContentEncodingHeader, checkinContentEncodingGzip)
	}

	cp := fmt.Sprintf(checkingPath, e.info.AgentID())
	sendStart := time.Now()
	resp, err := e.client.Send(ctx, http.MethodPost, cp, nil, requestHeaders, requestBody)
	sendDuration := time.Since(sendStart)
	if err != nil {
		return nil, sendDuration, fmt.Errorf("fail to checkin to fleet-server (uri: %s): %w", cp, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, sendDuration, extractError(resp.Body)
	}

	rs, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, sendDuration, fmt.Errorf("failed to read checkin response: %w", err)
	}

	checkinResponse := &CheckinResponse{}
	checkinResponse.FleetWarning = resp.Header.Get("Warning")
	decoder := json.NewDecoder(bytes.NewReader(rs))
	if err := decoder.Decode(checkinResponse); err != nil {
		return nil, sendDuration, fmt.Errorf("fail to decode checkin response (uri: %s): %w", cp, err)
	}

	if err := checkinResponse.Validate(); err != nil {
		return nil, sendDuration, err
	}

	return checkinResponse, sendDuration, nil
}

// extractError extracts an error from a fleet-server response body.
func extractError(resp io.Reader) error {
	e := &struct {
		StatusCode int    `json:"statusCode"`
		Error      string `json:"error"`
		Message    string `json:"message"`
	}{}

	data, err := io.ReadAll(resp)
	if err != nil {
		return fmt.Errorf("fail to read original error: %w", err)
	}

	err = json.Unmarshal(data, e)
	if err == nil {
		if len(e.Message) == 0 {
			return fmt.Errorf("status code: %d, fleet-server returned an error: %s", e.StatusCode, e.Error)
		}
		return fmt.Errorf(
			"status code: %d, fleet-server returned an error: %s, message: %s",
			e.StatusCode,
			e.Error,
			e.Message,
		)
	}

	return fmt.Errorf("could not decode the response, raw response: %s", string(data))
}

func gzipEncodeCheckinRequestBody(body []byte) (*bytes.Buffer, error) {
	compressedBody := bytes.NewBuffer(nil)
	gzipWriter := gzip.NewWriter(compressedBody)
	if _, err := gzipWriter.Write(body); err != nil {
		return nil, err
	}

	if err := gzipWriter.Close(); err != nil {
		return nil, err
	}

	return compressedBody, nil
}
