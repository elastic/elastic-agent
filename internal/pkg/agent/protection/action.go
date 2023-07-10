// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package protection

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/elastic/elastic-agent/internal/pkg/fleetapi"
)

var (
	ErrNonMatchingAgentID     = errors.New("non-matching agent id")
	ErrNonMatchingActionID    = errors.New("non-matching action id")
	ErrInvalidSignedDataValue = errors.New("invalid signed data value")
	ErrInvalidSignatureValue  = errors.New("invalid signature value")
)

type fleetActionWithAgents struct {
	ActionID         string          `json:"action_id"` // Note the action_id here, since the signed action uses action_id for id
	ActionType       string          `json:"type,omitempty"`
	InputType        string          `json:"input_type,omitempty"`
	Timestamp        string          `json:"@timestamp"`
	ActionExpiration string          `json:"expiration,omitempty"`
	ActionStartTime  string          `json:"start_time,omitempty"`
	Timeout          int64           `json:"timeout,omitempty"`
	Data             json.RawMessage `json:"data,omitempty"`
	Agents           []string        `json:"agents"`
}

// ValidateAction validates action signature, checks the signed payload action id matches the action id, checks the agent id match
func ValidateAction(a fleetapi.ActionApp, signatureValidationKey []byte, agentID string) (fleetapi.ActionApp, error) {
	// Nothing to validate if not signed
	if a.Signed == nil {
		return a, nil
	}

	data, err := base64.StdEncoding.DecodeString(a.Signed.Data)
	if err != nil {
		//nolint:errorlint // WAD: unfortunately two errors wrapping is only available in Go 1.20
		return a, fmt.Errorf("%w: %v", ErrInvalidSignedDataValue, err)
	}

	signature, err := base64.StdEncoding.DecodeString(a.Signed.Signature)
	if err != nil {
		//nolint:errorlint // WAD: unfortunately two errors wrapping is only available in Go 1.20
		return a, fmt.Errorf("%w: %v", ErrInvalidSignatureValue, err)
	}

	if len(signatureValidationKey) != 0 {
		// Validate signature
		err = ValidateSignature(data, signature, signatureValidationKey)
		if err != nil {
			return a, err
		}
	}

	// Deserialize signed action data if it's a valid JSON
	var fa fleetActionWithAgents
	err = json.Unmarshal(data, &fa)
	if err != nil {
		//nolint:errorlint // WAD: unfortunately two errors wrapping is only available in Go 1.20
		return a, fmt.Errorf("%w: %v", ErrInvalidSignedDataValue, err)
	}

	// Check if the action id is matching with the signed action id
	if a.ActionID != fa.ActionID {
		return a, ErrNonMatchingActionID
	}

	// Check if the signed action agents ids contain the agent id passed
	if !contains(fa.Agents, agentID) {
		return a, ErrNonMatchingAgentID
	}

	// Copy fields from signed fleet action document
	a.InputType = fa.InputType
	a.Timeout = fa.Timeout
	a.Data = fa.Data

	return a, nil
}

func contains[T comparable](arr []T, val T) bool {
	for _, v := range arr {
		if v == val {
			return true
		}
	}
	return false
}
