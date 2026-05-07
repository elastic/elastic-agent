// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package info

import (
	"context"
	"errors"
	"testing"

	"github.com/elastic/elastic-agent/pkg/utils"

	"github.com/stretchr/testify/assert"
)

type fakeAgentInfoStore struct {
	loaded  *AgentInfo
	loadErr error
	state   map[string]interface{}
}

func (f *fakeAgentInfoStore) Load(_ context.Context) (*AgentInfo, error) {
	if f.loadErr != nil {
		return nil, f.loadErr
	}
	return f.loaded, nil
}

func (f *fakeAgentInfoStore) Save(_ context.Context, opts ...SaveOption) error {
	if f.state == nil {
		f.state = map[string]interface{}{}
	}
	for _, o := range opts {
		o(f.state)
	}
	return nil
}

func TestNewAgentInfoWithLog(t *testing.T) {
	hasRoot, err := utils.HasRoot()
	assert.NoError(t, err, "failed to check for root")

	for _, tc := range []struct {
		name            string
		loaded          *AgentInfo
		defaultLogLevel string
		expected        *AgentInfo
	}{
		{
			name:            "standalone uses the supplied default in memory",
			loaded:          &AgentInfo{AgentID: "testID", LogLevelPolicy: "info", isStandalone: true},
			defaultLogLevel: "debug",
			expected:        &AgentInfo{AgentID: "testID", LogLevelPolicy: "debug", unprivileged: !hasRoot, isStandalone: true},
		},
		{
			name:            "fleet keeps the on-disk policy level",
			loaded:          &AgentInfo{AgentID: "testID", LogLevelPolicy: "info", isStandalone: false},
			defaultLogLevel: "debug",
			expected:        &AgentInfo{AgentID: "testID", LogLevelPolicy: "info", unprivileged: !hasRoot, isStandalone: false},
		},
		{
			name:            "fleet with per-agent override",
			loaded:          &AgentInfo{AgentID: "testID", LogLevelPolicy: "info", LogLevelOverride: "warning", isStandalone: false},
			defaultLogLevel: "debug",
			expected:        &AgentInfo{AgentID: "testID", LogLevelPolicy: "info", LogLevelOverride: "warning", unprivileged: !hasRoot, isStandalone: false},
		},
		{
			name:            "fleet without persisted level applies and persists the default",
			loaded:          &AgentInfo{AgentID: "x", isStandalone: false},
			defaultLogLevel: "info",
			expected:        &AgentInfo{AgentID: "x", LogLevelPolicy: "info", unprivileged: !hasRoot, isStandalone: false},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			setFakeStore(t, tc.loaded, nil)
			ai, err := NewAgentInfoWithLog(t.Context(), tc.defaultLogLevel, false)
			assert.NoError(t, err)
			assert.Equal(t, tc.expected, ai)
		})
	}
}

func TestNewAgentInfoWithLog_PersistsDefaultLevelInFleetModeWhenMissing(t *testing.T) {
	fake := setFakeStore(t, &AgentInfo{AgentID: "x", isStandalone: false}, nil)

	_, err := NewAgentInfoWithLog(context.Background(), "info", false)
	assert.NoError(t, err)

	logging := fake.state["agent"].(map[string]interface{})["logging"].(map[string]interface{})
	assert.Equal(t, "info", logging["level"])
}

func TestNewAgentInfoWithLog_GeneratesAgentIDWhenMissing(t *testing.T) {
	fake := setFakeStore(t, &AgentInfo{isStandalone: true}, nil)

	ai, err := NewAgentInfoWithLog(context.Background(), "info", true)
	assert.NoError(t, err)
	assert.NotEmpty(t, ai.AgentID, "a new agent ID should have been generated")

	saved := fake.state["agent"].(map[string]interface{})
	assert.Equal(t, ai.AgentID, saved["id"], "agent.id should be persisted")
}

func TestNewAgentInfoWithLog_LoadErrorPropagates(t *testing.T) {
	wantErr := errors.New("disk read failed")
	setFakeStore(t, nil, wantErr)

	_, err := NewAgentInfoWithLog(context.Background(), "info", true)
	assert.ErrorIs(t, err, wantErr)
}

// setFakeStore swaps in a fakeAgentInfoStore for the duration of the test and
// returns it so callers can inspect what was persisted.
func setFakeStore(t *testing.T, loaded *AgentInfo, loadErr error) *fakeAgentInfoStore {
	t.Helper()
	prev := defaultAgentInfoStore
	t.Cleanup(func() { defaultAgentInfoStore = prev })
	fake := &fakeAgentInfoStore{loaded: loaded, loadErr: loadErr}
	defaultAgentInfoStore = fake
	return fake
}
