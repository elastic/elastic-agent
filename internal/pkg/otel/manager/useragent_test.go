// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package manager

import (
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"

	fbfeatures "github.com/elastic/beats/v7/libbeat/features"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
	"github.com/elastic/elastic-agent/internal/pkg/release"
)

func TestGenerateUserAgent(t *testing.T) {
	fips := ""
	if release.FIPSDistribution() {
		fips = "; FIPS"
	}
	platform := runtime.GOOS + "; " + runtime.GOARCH

	testCases := []struct {
		name         string
		standalone   bool
		unprivileged bool
		agentless    bool
		expected     string
	}{
		{
			name:     "fleet managed, privileged",
			expected: "Elastic-Agent/9.9.9 (" + platform + "; Managed; Privileged" + fips + ")",
		},
		{
			name:         "standalone, unprivileged",
			standalone:   true,
			unprivileged: true,
			expected:     "Elastic-Agent/9.9.9 (" + platform + "; Unmanaged; Unprivileged" + fips + ")",
		},
		{
			name:      "agentless",
			agentless: true,
			expected:  "Elastic-Agent/9.9.9 (" + platform + "; Managed; Privileged" + fips + "; agentless)",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.agentless {
				t.Setenv("AGENTLESS_ELASTICSEARCH_STATE_STORE_INPUT_TYPES", "cel")
				fbfeatures.ReinitForTest()
				// Registered after Setenv so it runs after the env var is restored.
				t.Cleanup(fbfeatures.ReinitForTest)
			}
			agentInfo := info.NewMockAgent(t)
			agentInfo.EXPECT().Version().Return("9.9.9")
			agentInfo.EXPECT().IsStandalone().Return(tc.standalone)
			agentInfo.EXPECT().Unprivileged().Return(tc.unprivileged)

			assert.Equal(t, tc.expected, generateUserAgent(agentInfo), "user agent should match the libbeat format")
		})
	}
}
