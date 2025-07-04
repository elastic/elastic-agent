// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package info

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/pkg/utils"

	"github.com/stretchr/testify/assert"
)

func TestNewAgentInfoWithLog(t *testing.T) {
	hasRoot, err := utils.HasRoot()
	require.NoError(t, err, "failed to check for root")

	for _, tc := range []struct {
		name                string
		levelFromConfig     string
		isStandalone        bool
		persistentAgentInfo *persistentAgentInfo
		expected            *AgentInfo
	}{
		{
			name:            "standalone agent",
			levelFromConfig: "debug",
			isStandalone:    true,
			persistentAgentInfo: &persistentAgentInfo{
				ID:             "testID",
				Headers:        nil,
				LogLevel:       "info",
				MonitoringHTTP: nil,
			},
			expected: &AgentInfo{
				agentID:      "testID",
				logLevel:     "debug",
				unprivileged: !hasRoot,
				esHeaders:    nil,
				isStandalone: true,
			},
		},
		{
			name:            "fleet managed agent",
			levelFromConfig: "debug",
			isStandalone:    false,
			persistentAgentInfo: &persistentAgentInfo{
				ID:             "testID",
				Headers:        nil,
				LogLevel:       "info",
				MonitoringHTTP: nil,
			},
			expected: &AgentInfo{
				agentID:      "testID",
				logLevel:     "info",
				unprivileged: !hasRoot,
				esHeaders:    nil,
				isStandalone: false,
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			prevDoLoadAgentInfoWithBackoff := doLoadAgentInfoWithBackoff
			defer func() {
				doLoadAgentInfoWithBackoff = prevDoLoadAgentInfoWithBackoff
			}()
			doLoadAgentInfoWithBackoff = func(ctx context.Context, forceUpdate bool, logLevel string, createAgentID bool) (*persistentAgentInfo, bool, error) {
				return tc.persistentAgentInfo, tc.isStandalone, nil
			}

			ai, err := NewAgentInfoWithLog(context.Background(), tc.levelFromConfig, true)
			assert.NoError(t, err, "could not create agent info")
			assert.Equal(t, tc.expected, ai, "agent info does not match")
		})
	}
}
