// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package fleetcontract

import (
	"encoding/json"
	"time"
)

// CheckinRequest is the payload sent to Fleet Server's checkin endpoint.
//
// Fields that carry consumer-specific types (e.g. local metadata, upgrade
// details) use json.RawMessage so that both the full Elastic Agent and
// lightweight emulators can populate them without sharing internal type
// definitions.
type CheckinRequest struct {
	Status            string             `json:"status"`
	AckToken          string             `json:"ack_token,omitempty"`
	Metadata          json.RawMessage    `json:"local_metadata,omitempty"`
	Message           string             `json:"message"`
	Components        []CheckinComponent `json:"components"`
	UpgradeDetails    json.RawMessage    `json:"upgrade_details,omitempty"`
	AgentPolicyID     string             `json:"agent_policy_id,omitempty"`
	PolicyRevisionIDX int64              `json:"policy_revision_idx,omitempty"`
	Upgrade           CheckinUpgrade     `json:"upgrade,omitempty"`
}

// CheckinComponent provides information about a component during checkin.
type CheckinComponent struct {
	ID      string        `json:"id"`
	Type    string        `json:"type"`
	Status  string        `json:"status"`
	Message string        `json:"message"`
	Units   []CheckinUnit `json:"units,omitempty"`
}

// CheckinUnit provides information about a unit within a component during checkin.
type CheckinUnit struct {
	ID      string                 `json:"id"`
	Type    string                 `json:"type"`
	Status  string                 `json:"status"`
	Message string                 `json:"message"`
	Payload map[string]interface{} `json:"payload,omitempty"`
}

// CheckinRollback describes an available rollback version.
type CheckinRollback struct {
	Version    string    `json:"version"`
	ValidUntil time.Time `json:"valid_until"`
}

// CheckinUpgrade carries rollback information in the checkin request.
type CheckinUpgrade struct {
	Rollbacks []CheckinRollback `json:"rollbacks,omitempty"`
}

// CheckinResponse is the response from Fleet Server's checkin endpoint.
type CheckinResponse struct {
	AckToken     string          `json:"ack_token"`
	Actions      json.RawMessage `json:"actions"`
	FleetWarning string          `json:"-"`
}
