// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package fleetcontract

import (
	"encoding/json"
	"time"
)

// EnrollType is the type of enrollment to do with the elastic-agent.
type EnrollType string

const (
	// PermanentEnroll is default enrollment type.
	PermanentEnroll EnrollType = "PERMANENT"
)

// EnrollRequest is the payload sent to Fleet Server's enroll endpoint.
type EnrollRequest struct {
	EnrollAPIKey string     `json:"-"`
	Type         EnrollType `json:"type"`
	ID           string     `json:"id,omitempty"`
	ReplaceToken string     `json:"replace_token,omitempty"`
	Metadata     EnrollMeta `json:"metadata"`
}

// EnrollMeta carries metadata sent during enrollment.
type EnrollMeta struct {
	Local        json.RawMessage        `json:"local"`
	UserProvided map[string]interface{} `json:"user_provided"`
	Tags         []string               `json:"tags,omitempty"`
}

// EnrollResponse is the response from Fleet Server's enroll endpoint.
type EnrollResponse struct {
	Action string             `json:"action"`
	Item   EnrollItemResponse `json:"item"`
}

// EnrollItemResponse contains the enrolled agent details.
type EnrollItemResponse struct {
	ID                   string                 `json:"id"`
	Active               bool                   `json:"active"`
	PolicyID             string                 `json:"policy_id"`
	Type                 EnrollType             `json:"type"`
	EnrolledAt           time.Time              `json:"enrolled_at"`
	UserProvidedMetadata map[string]interface{} `json:"user_provided_metadata"`
	LocalMetadata        map[string]interface{} `json:"local_metadata"`
	Actions              []interface{}          `json:"actions"`
	AccessAPIKey         string                 `json:"access_api_key"`
	Tags                 []string               `json:"tags"`
}
