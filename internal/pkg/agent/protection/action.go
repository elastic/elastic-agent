// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package protection

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/elastic/elastic-agent/internal/pkg/fleetapi"
)

var (
	ErrNotSigned              = errors.New("not signed")
	ErrNonMatchingAgentID     = errors.New("non-matching agent id")
	ErrNonMatchingActionID    = errors.New("non-matching action id")
	ErrNonMatchingActionType  = errors.New("non-matching action type")
	ErrInvalidSignedDataValue = errors.New("invalid signed data value")
	ErrInvalidSignatureValue  = errors.New("invalid signature value")
)

type signedAction interface {
	ID() string
	Type() string
	Signed() *fleetapi.Signed
}

type actionWithData struct {
	ActionID   string          `json:"action_id"`
	ActionType string          `json:"type,omitempty"`
	Data       json.RawMessage `json:"data" mapstructure:"data"`
	Agents     []string        `json:"agents"`
}

// ValidateAction validates action signature, checks the signed payload action id matches the action id, checks the agent id match
// Returns decoded data.
// In case data has no `signed` information ErrNotSigned error is returned.
func ValidateAction(a signedAction, signatureValidationKey []byte, agentID string) (json.RawMessage, error) {
	// Nothing to validate if not signed
	if a.Signed() == nil {
		return nil, ErrNotSigned
	}

	data, err := base64.StdEncoding.DecodeString(a.Signed().Data)
	if err != nil {
		//nolint:errorlint // WAD: unfortunately two errors wrapping is only available in Go 1.20
		return nil, fmt.Errorf("%w: %v", ErrInvalidSignedDataValue, err)
	}

	signature, err := base64.StdEncoding.DecodeString(a.Signed().Signature)
	if err != nil {
		//nolint:errorlint // WAD: unfortunately two errors wrapping is only available in Go 1.20
		return nil, fmt.Errorf("%w: %v", ErrInvalidSignatureValue, err)
	}

	if len(signatureValidationKey) != 0 {
		// Validate signature
		err = ValidateSignature(data, signature, signatureValidationKey)
		if err != nil {
			return nil, err
		}
	}

	// Deserialize signed action data if it's a valid JSON
	var fa actionWithData
	err = json.Unmarshal(data, &fa)
	if err != nil {
		//nolint:errorlint // WAD: unfortunately two errors wrapping is only available in Go 1.20
		return nil, fmt.Errorf("%w: %v", ErrInvalidSignedDataValue, err)
	}

	// Check if the action id is matching with the signed action id
	if a.ID() != fa.ActionID {
		return nil, ErrNonMatchingActionID
	}

	// Check type
	if a.Type() != fa.ActionType {
		return nil, ErrNonMatchingActionType
	}

	// Check if the signed action agents ids contain the agent id passed
	if !contains(fa.Agents, agentID) {
		return nil, ErrNonMatchingAgentID
	}

	return fa.Data, nil
}

func contains[T comparable](arr []T, val T) bool {
	for _, v := range arr {
		if v == val {
			return true
		}
	}
	return false
}
