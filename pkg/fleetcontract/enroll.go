// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package fleetcontract

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// EnrollType is the type of enrollment to do with the elastic-agent.
type EnrollType string

const (
	// PermanentEnroll is default enrollment type.
	PermanentEnroll EnrollType = "PERMANENT"
)

var mapEnrollType = map[string]EnrollType{
	"PERMANENT": PermanentEnroll,
}

var reverseMapEnrollType = make(map[EnrollType]string)

func init() {
	for k, v := range mapEnrollType {
		reverseMapEnrollType[v] = k
	}
}

// UnmarshalJSON validates and unmarshals an enrollment type.
func (p *EnrollType) UnmarshalJSON(b []byte) error {
	s := string(b)
	if len(s) <= 2 {
		return errors.New("invalid enroll type received")
	}
	s = s[1 : len(s)-1]
	v, ok := mapEnrollType[s]
	if !ok {
		return fmt.Errorf("value of '%s' is an invalid enrollment type, supported type is 'PERMANENT'", s)
	}
	*p = v
	return nil
}

// MarshalJSON marshals an enrollment type.
func (p EnrollType) MarshalJSON() ([]byte, error) {
	v, ok := reverseMapEnrollType[p]
	if !ok {
		return nil, errors.New("cannot serialize unknown type")
	}
	return json.Marshal(v)
}

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

// Validate validates the enrollment response returned by Fleet Server.
func (e *EnrollResponse) Validate() error {
	var errs []error
	if len(e.Item.ID) == 0 {
		errs = append(errs, errors.New("missing ID"))
	}
	if len(e.Item.Type) == 0 {
		errs = append(errs, errors.New("missing enrollment type"))
	}
	if len(e.Item.AccessAPIKey) == 0 {
		errs = append(errs, errors.New("access api key is missing"))
	}
	return errors.Join(errs...)
}
