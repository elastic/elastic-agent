// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package fleetcontract

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestActionRoundTrip(t *testing.T) {
	now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	a := Action{
		ID:        "action-1",
		Type:      ActionTypeUpgrade,
		Data:      json.RawMessage(`{"version":"9.0.0"}`),
		CreatedAt: now,
	}

	b, err := json.Marshal(a)
	require.NoError(t, err)

	var decoded Action
	require.NoError(t, json.Unmarshal(b, &decoded))
	assert.Equal(t, a.ID, decoded.ID)
	assert.Equal(t, a.Type, decoded.Type)
	assert.JSONEq(t, `{"version":"9.0.0"}`, string(decoded.Data))
}

func TestCheckinRequestJSON(t *testing.T) {
	req := CheckinRequest{
		Status:        "online",
		AckToken:      "tok-1",
		Message:       "Running",
		AgentPolicyID: "policy-1",
	}

	b, err := json.Marshal(req)
	require.NoError(t, err)

	var m map[string]interface{}
	require.NoError(t, json.Unmarshal(b, &m))

	assert.Equal(t, "online", m["status"])
	assert.Equal(t, "tok-1", m["ack_token"])
	assert.Equal(t, "Running", m["message"])
	assert.Equal(t, "policy-1", m["agent_policy_id"])
}

func TestCheckinResponseJSON(t *testing.T) {
	raw := `{
		"ack_token": "tok-2",
		"actions": [{"id":"a1","type":"POLICY_CHANGE"}]
	}`
	var resp CheckinResponse
	require.NoError(t, json.Unmarshal([]byte(raw), &resp))
	assert.Equal(t, "tok-2", resp.AckToken)
	assert.NotEmpty(t, resp.Actions)
	assert.Empty(t, resp.FleetWarning, "FleetWarning should not be populated from JSON")
}

func TestAckEventJSON(t *testing.T) {
	evt := AckEvent{
		EventType: "ACTION_RESULT",
		SubType:   "ACKNOWLEDGED",
		Timestamp: "2025-01-01T00:00:00Z",
		ActionID:  "action-1",
		AgentID:   "agent-1",
	}

	b, err := json.Marshal(evt)
	require.NoError(t, err)

	var m map[string]interface{}
	require.NoError(t, json.Unmarshal(b, &m))
	assert.Equal(t, "ACTION_RESULT", m["type"])
	assert.Equal(t, "ACKNOWLEDGED", m["subtype"])
}

func TestEnrollRequestJSON(t *testing.T) {
	req := EnrollRequest{
		EnrollAPIKey: "secret-key",
		Type:         PermanentEnroll,
		Metadata: EnrollMeta{
			Local: json.RawMessage(`{"os":"linux"}`),
		},
	}

	b, err := json.Marshal(req)
	require.NoError(t, err)

	var m map[string]interface{}
	require.NoError(t, json.Unmarshal(b, &m))
	assert.Equal(t, "PERMANENT", m["type"])
	assert.Nil(t, m["enroll_api_key"], "EnrollAPIKey must not appear in JSON")
}

func TestSentinelErrors(t *testing.T) {
	assert.True(t, errors.Is(ErrTooManyRequests, ErrTooManyRequests))
	assert.True(t, errors.Is(ErrConnRefused, ErrConnRefused))
	assert.True(t, errors.Is(ErrTemporaryServerError, ErrTemporaryServerError))
	assert.True(t, errors.Is(ErrInvalidToken, ErrInvalidToken))
	assert.True(t, errors.Is(ErrInvalidAPIKey, ErrInvalidAPIKey))
	assert.False(t, errors.Is(ErrInvalidToken, ErrInvalidAPIKey))
}
