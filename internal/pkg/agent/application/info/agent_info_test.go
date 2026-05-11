// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package info

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/elastic/elastic-agent/pkg/utils"
)

func TestNewAgentInfoWithLog(t *testing.T) {
	hasRoot, err := utils.HasRoot()
	assert.NoError(t, err, "failed to check for root")

	for _, tc := range []struct {
		name            string
		loaded          *persistentAgentInfo
		isStandalone    bool
		defaultLogLevel string
		expected        *AgentInfo
	}{
		{
			name:            "standalone uses the supplied default in memory",
			loaded:          &persistentAgentInfo{ID: "testID", LogLevel: "info"},
			isStandalone:    true,
			defaultLogLevel: "debug",
			expected:        &AgentInfo{agentID: "testID", logLevelPolicy: "debug", unprivileged: !hasRoot, isStandalone: true},
		},
		{
			name:            "fleet keeps the on-disk policy level",
			loaded:          &persistentAgentInfo{ID: "testID", LogLevel: "info"},
			isStandalone:    false,
			defaultLogLevel: "debug",
			expected:        &AgentInfo{agentID: "testID", logLevelPolicy: "info", unprivileged: !hasRoot, isStandalone: false},
		},
		{
			name:            "fleet with per-agent override",
			loaded:          &persistentAgentInfo{ID: "testID", LogLevel: "info", LogLevelOverride: "warning"},
			isStandalone:    false,
			defaultLogLevel: "debug",
			expected:        &AgentInfo{agentID: "testID", logLevelPolicy: "info", logLevelOverride: "warning", unprivileged: !hasRoot, isStandalone: false},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			setFakeLoader(t, tc.loaded, tc.isStandalone, nil)
			ai, err := NewAgentInfoWithLog(t.Context(), tc.defaultLogLevel, false)
			assert.NoError(t, err)
			assert.Equal(t, tc.expected, ai)
		})
	}
}

func TestNewAgentInfoWithLog_LoadErrorPropagates(t *testing.T) {
	wantErr := errors.New("disk read failed")
	setFakeLoader(t, nil, false, wantErr)

	_, err := NewAgentInfoWithLog(context.Background(), "info", true)
	assert.ErrorIs(t, err, wantErr)
}

// setFakeLoader swaps out doLoadAgentInfoWithBackoff for the duration of the
// test so the disk-load path can be stubbed without a real encrypted vault.
func setFakeLoader(t *testing.T, loaded *persistentAgentInfo, isStandalone bool, loadErr error) {
	t.Helper()
	prev := doLoadAgentInfoWithBackoff
	t.Cleanup(func() { doLoadAgentInfoWithBackoff = prev })
	doLoadAgentInfoWithBackoff = func(_ context.Context, _ bool, logLevel string, _ bool) (*persistentAgentInfo, bool, error) {
		if loadErr != nil {
			return nil, false, loadErr
		}
		return loaded, isStandalone, nil
	}
}
