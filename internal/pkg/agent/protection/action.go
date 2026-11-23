// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package protection

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/elastic/elastic-agent/pkg/fleetapi"
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
	Expiration string          `json:"expiration,omitempty"`
}

// VerifiedAction holds the fields extracted from a verified signed action
// envelope. Callers should trust these values over the action's mutable outer
// JSON, since only the signed payload is covered by the signature.
type VerifiedAction struct {
	// Data is the signed payload's nested data field.
	Data json.RawMessage
	// Expiration is the signed payload's expiration (empty when the signed
	// envelope carries no expiration).
	Expiration string
}

// VerifyActionSignature reports an error when the action's signature is required
// but missing or invalid. When a signatureValidationKey is configured the action
// must be signed and valid; when no key is configured an unsigned action is
// accepted (no verification is performed). It is a thin gate over the shared
// signature validation, used by callers that only care whether the action may
// proceed.
//
// On success it returns the verified fields from the signed envelope, or nil when
// the action carries no signature. Callers should prefer these verified fields
// over the action's mutable outer fields so that fields covered by the signature
// cannot be tampered with while keeping a valid signature.
func VerifyActionSignature(a signedAction, signatureValidationKey []byte, agentID string) (*VerifiedAction, error) {
	fa, err := validateAction(a, signatureValidationKey, agentID)
	if errors.Is(err, ErrNotSigned) && len(signatureValidationKey) == 0 {
		// No key configured and the action is unsigned: accepted, but there are
		// no verified fields to return.
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &VerifiedAction{Data: fa.Data, Expiration: fa.Expiration}, nil
}

// ValidateAction validates action signature, checks the signed payload action id matches the action id, checks the agent id match
// Returns decoded data.
// In case data has no `signed` information ErrNotSigned error is returned.
func ValidateAction(a signedAction, signatureValidationKey []byte, agentID string) (json.RawMessage, error) {
	fa, err := validateAction(a, signatureValidationKey, agentID)
	if err != nil {
		return nil, err
	}
	return fa.Data, nil
}

// validateAction verifies the signature and cross-checks the signed envelope
// against the action, returning the full parsed signed payload on success.
func validateAction(a signedAction, signatureValidationKey []byte, agentID string) (actionWithData, error) {
	// Nothing to validate if not signed
	if a.Signed() == nil {
		return actionWithData{}, ErrNotSigned
	}

	data, err := base64.StdEncoding.DecodeString(a.Signed().Data)
	if err != nil {
		//nolint:errorlint // WAD: unfortunately two errors wrapping is only available in Go 1.20
		return actionWithData{}, fmt.Errorf("%w: %v", ErrInvalidSignedDataValue, err)
	}

	signature, err := base64.StdEncoding.DecodeString(a.Signed().Signature)
	if err != nil {
		//nolint:errorlint // WAD: unfortunately two errors wrapping is only available in Go 1.20
		return actionWithData{}, fmt.Errorf("%w: %v", ErrInvalidSignatureValue, err)
	}

	if len(signatureValidationKey) != 0 {
		// Validate signature
		err = ValidateSignature(data, signature, signatureValidationKey)
		if err != nil {
			return actionWithData{}, err
		}
	}

	// Deserialize signed action data if it's a valid JSON
	var fa actionWithData
	err = json.Unmarshal(data, &fa)
	if err != nil {
		//nolint:errorlint // WAD: unfortunately two errors wrapping is only available in Go 1.20
		return actionWithData{}, fmt.Errorf("%w: %v", ErrInvalidSignedDataValue, err)
	}

	// Check if the action id is matching with the signed action id
	if a.ID() != fa.ActionID {
		return actionWithData{}, ErrNonMatchingActionID
	}

	// Check type
	if a.Type() != fa.ActionType {
		return actionWithData{}, ErrNonMatchingActionType
	}

	// Check if the signed action agents ids contain the agent id passed
	if !contains(fa.Agents, agentID) {
		return actionWithData{}, ErrNonMatchingAgentID
	}

	return fa, nil
}

func contains[T comparable](arr []T, val T) bool {
	for _, v := range arr {
		if v == val {
			return true
		}
	}
	return false
}
