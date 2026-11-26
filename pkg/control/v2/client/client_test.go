// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package client

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/pkg/control/v2/cproto"
)

func TestToStateCPULimit(t *testing.T) {
	testcases := []struct {
		name     string
		cpuLimit *cproto.CPULimit
		expected *CPULimitState
	}{
		{
			name: "degraded with error",
			cpuLimit: &cproto.CPULimit{
				State:              "degraded",
				ConfiguredPercent:  50,
				TargetCpus:         4,
				ActiveQuota:        "set",
				ActiveQuotaCpus:    2.5,
				EffectiveQuota:     "set",
				EffectiveQuotaCpus: 1.5,
				Error:              "set failed",
			},
			expected: &CPULimitState{
				State:              "degraded",
				ConfiguredPercent:  50,
				TargetCPUs:         4,
				ActiveQuota:        "set",
				ActiveQuotaCPUs:    2.5,
				EffectiveQuota:     "set",
				EffectiveQuotaCPUs: 1.5,
				Error:              "set failed",
			},
		},
		{
			name: "unsupported with reason",
			cpuLimit: &cproto.CPULimit{
				State:             "unsupported",
				ConfiguredPercent: 25,
				TargetCpus:        1.5,
				ActiveQuota:       "unknown",
				EffectiveQuota:    "none",
				Reason:            "not supported here",
			},
			expected: &CPULimitState{
				State:             "unsupported",
				ConfiguredPercent: 25,
				TargetCPUs:        1.5,
				ActiveQuota:       "unknown",
				EffectiveQuota:    "none",
				Reason:            "not supported here",
			},
		},
		{
			name: "cap of 100 is a normal cap",
			cpuLimit: &cproto.CPULimit{
				State:              "applied",
				ConfiguredPercent:  100,
				TargetCpus:         4,
				ActiveQuota:        "set",
				ActiveQuotaCpus:    4,
				EffectiveQuota:     "set",
				EffectiveQuotaCpus: 4,
			},
			expected: &CPULimitState{
				State:              "applied",
				ConfiguredPercent:  100,
				TargetCPUs:         4,
				ActiveQuota:        "set",
				ActiveQuotaCPUs:    4,
				EffectiveQuota:     "set",
				EffectiveQuotaCPUs: 4,
			},
		},
		{
			// The JSON and YAML output show the same text for an unknown effective quota as the human output.
			name: "message without the effective quota fields",
			cpuLimit: &cproto.CPULimit{
				State:             "applied",
				ConfiguredPercent: 50,
				TargetCpus:        2,
				ActiveQuota:       "set",
				ActiveQuotaCpus:   2,
			},
			expected: &CPULimitState{
				State:             "applied",
				ConfiguredPercent: 50,
				TargetCPUs:        2,
				ActiveQuota:       "set",
				ActiveQuotaCPUs:   2,
				EffectiveQuota:    "unknown",
			},
		},
		{
			name: "unknown state and quota kind from a newer agent are kept",
			cpuLimit: &cproto.CPULimit{
				State:             "throttled",
				ConfiguredPercent: 50,
				ActiveQuota:       "partial",
				EffectiveQuota:    "partial",
			},
			expected: &CPULimitState{
				State:             "throttled",
				ConfiguredPercent: 50,
				ActiveQuota:       "partial",
				EffectiveQuota:    "partial",
			},
		},
		{
			name: "cap off",
			cpuLimit: &cproto.CPULimit{
				State:          "disabled",
				ActiveQuota:    "unknown",
				EffectiveQuota: "unknown",
			},
			expected: &CPULimitState{
				State:          "disabled",
				ActiveQuota:    "unknown",
				EffectiveQuota: "unknown",
			},
		},
		{
			name:     "response from an agent without the field",
			cpuLimit: nil,
			expected: nil,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			s, err := toState(&cproto.StateResponse{Info: &cproto.StateAgentInfo{}, CpuLimit: tc.cpuLimit})
			require.NoError(t, err)
			assert.Equal(t, tc.expected, s.CPULimit)
		})
	}
}
