// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package fleetcontract

import (
	"encoding/json"
	"time"
)

const (
	ActionTypeUnknown              = "UNKNOWN"
	ActionTypeUpgrade              = "UPGRADE"
	ActionTypeUnenroll             = "UNENROLL"
	ActionTypePolicyChange         = "POLICY_CHANGE"
	ActionTypePolicyReassign       = "POLICY_REASSIGN"
	ActionTypeSettings             = "SETTINGS"
	ActionTypeInputAction          = "INPUT_ACTION"
	ActionTypeCancel               = "CANCEL"
	ActionTypeDiagnostics          = "REQUEST_DIAGNOSTICS"
	ActionTypeMigrate              = "MIGRATE"
	ActionTypePrivilegeLevelChange = "PRIVILEGE_LEVEL_CHANGE"
)

// Action represents the base fields of a Fleet action returned in a checkin
// response. Both the full Elastic Agent and lightweight emulators (e.g. Horde
// drones) receive actions in this shape; each consumer interprets the Data
// payload according to its own needs.
type Action struct {
	ID          string          `json:"id"`
	Type        string          `json:"type"`
	InputType   string          `json:"input_type,omitempty"`
	Data        json.RawMessage `json:"data,omitempty"`
	CreatedAt   time.Time       `json:"created_at,omitempty"`
	StartTime   *time.Time      `json:"start_time,omitempty"`
	Expiration  *time.Time      `json:"expiration,omitempty"`
	Traceparent string          `json:"traceparent,omitempty"`
}

// Signed contains the signed data and signature for action verification.
type Signed struct {
	Data      string `json:"data"`
	Signature string `json:"signature"`
}
