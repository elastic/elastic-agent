// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//nolint:dupl // duplicate code is in test cases
package fleetapi

import (
	"encoding/json"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestActionSerialization(t *testing.T) {
	a := ActionApp{
		ActionID:   "1231232",
		ActionType: "APP_INPUT",
		InputType:  "osquery",
		Data:       []byte(`{ "foo": "bar" }`),
	}

	m, err := a.MarshalMap()
	if err != nil {
		t.Fatal(err)
	}

	diff := cmp.Diff(4, len(m))
	if diff != "" {
		t.Error(diff)
	}

	diff = cmp.Diff(a.ActionID, mapStringVal(m, "id"))
	if diff != "" {
		t.Error(diff)
	}

	diff = cmp.Diff(a.ActionType, mapStringVal(m, "type"))
	if diff != "" {
		t.Error(diff)
	}

	diff = cmp.Diff(a.InputType, mapStringVal(m, "input_type"))
	if diff != "" {
		t.Error(diff)
	}

	diff = cmp.Diff(a.Data, mapRawMessageVal(m, "data"))
	if diff != "" {
		t.Error(diff)
	}

	diff = cmp.Diff(a.StartedAt, mapStringVal(m, "started_at"))
	if diff != "" {
		t.Error(diff)
	}
	diff = cmp.Diff(a.CompletedAt, mapStringVal(m, "completed_at"))
	if diff != "" {
		t.Error(diff)
	}
	diff = cmp.Diff(a.Error, mapStringVal(m, "error"))
	if diff != "" {
		t.Error(diff)
	}
}

func mapStringVal(m map[string]interface{}, key string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func mapRawMessageVal(m map[string]interface{}, key string) json.RawMessage {
	if v, ok := m[key]; ok {
		if res, ok := v.(json.RawMessage); ok {
			return res
		}
	}
	return nil
}

func TestActionsUnmarshalJSON(t *testing.T) {
	t.Run("ActionUpgrade no start time", func(t *testing.T) {
		p := []byte(`[{"id":"testid","type":"UPGRADE","data":{"version":"1.2.3","source_uri":"http://example.com"}}]`)
		a := &Actions{}
		err := a.UnmarshalJSON(p)
		require.Nil(t, err)
		action, ok := (*a)[0].(*ActionUpgrade)
		require.True(t, ok, "unable to cast action to specific type")
		assert.Equal(t, "testid", action.ActionID)
		assert.Equal(t, ActionTypeUpgrade, action.ActionType)
		assert.Empty(t, action.ActionStartTime)
		assert.Empty(t, action.ActionExpiration)
		assert.Equal(t, "1.2.3", action.Version)
		assert.Equal(t, "http://example.com", action.SourceURI)
		assert.Equal(t, 0, action.Retry)
	})
	t.Run("ActionUpgrade with start time", func(t *testing.T) {
		p := []byte(`[{"id":"testid","type":"UPGRADE","start_time":"2022-01-02T12:00:00Z","expiration":"2022-01-02T13:00:00Z","data":{"version":"1.2.3","source_uri":"http://example.com"}}]`)
		a := &Actions{}
		err := a.UnmarshalJSON(p)
		require.Nil(t, err)
		action, ok := (*a)[0].(*ActionUpgrade)
		require.True(t, ok, "unable to cast action to specific type")
		assert.Equal(t, "testid", action.ActionID)
		assert.Equal(t, ActionTypeUpgrade, action.ActionType)
		assert.Equal(t, "2022-01-02T12:00:00Z", action.ActionStartTime)
		assert.Equal(t, "2022-01-02T13:00:00Z", action.ActionExpiration)
		assert.Equal(t, "1.2.3", action.Version)
		assert.Equal(t, "http://example.com", action.SourceURI)
		assert.Equal(t, 0, action.Retry)
	})
	t.Run("ActionPolicyChange no start time", func(t *testing.T) {
		p := []byte(`[{"id":"testid","type":"POLICY_CHANGE","data":{"policy":{"key":"value"}}}]`)
		a := &Actions{}
		err := a.UnmarshalJSON(p)
		require.Nil(t, err)
		action, ok := (*a)[0].(*ActionPolicyChange)
		require.True(t, ok, "unable to cast action to specific type")
		assert.Equal(t, "testid", action.ActionID)
		assert.Equal(t, ActionTypePolicyChange, action.ActionType)
		assert.NotNil(t, action.Policy)
	})
	t.Run("ActionPolicyChange with start time", func(t *testing.T) {
		p := []byte(`[{"id":"testid","type":"POLICY_CHANGE","start_time":"2022-01-02T12:00:00Z","expiration":"2022-01-02T13:00:00Z","data":{"policy":{"key":"value"}}}]`)
		a := &Actions{}
		err := a.UnmarshalJSON(p)
		require.Nil(t, err)
		action, ok := (*a)[0].(*ActionPolicyChange)
		require.True(t, ok, "unable to cast action to specific type")
		assert.Equal(t, "testid", action.ActionID)
		assert.Equal(t, ActionTypePolicyChange, action.ActionType)
		assert.NotNil(t, action.Policy)
	})
	t.Run("ActionUpgrade with retry_attempt", func(t *testing.T) {
		p := []byte(`[{"id":"testid","type":"UPGRADE","data":{"version":"1.2.3","source_uri":"http://example.com","retry_attempt":1}}]`)
		a := &Actions{}
		err := a.UnmarshalJSON(p)
		require.Nil(t, err)
		action, ok := (*a)[0].(*ActionUpgrade)
		require.True(t, ok, "unable to cast action to specific type")
		assert.Equal(t, "testid", action.ActionID)
		assert.Equal(t, ActionTypeUpgrade, action.ActionType)
		assert.Empty(t, action.ActionStartTime)
		assert.Empty(t, action.ActionExpiration)
		assert.Equal(t, "1.2.3", action.Version)
		assert.Equal(t, "http://example.com", action.SourceURI)
		assert.Equal(t, 1, action.Retry)
	})
}
