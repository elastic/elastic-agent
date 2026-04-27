// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package agentless

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsAgentless(t *testing.T) {
	testCases := []struct {
		shouldSetEnv bool
		name         string
		env          string
		want         bool
	}{
		{shouldSetEnv: false, name: "not set", env: "", want: false},
		{shouldSetEnv: true, name: "set", env: "", want: true},
		{shouldSetEnv: true, name: "set with value", env: "1", want: true},
		{shouldSetEnv: true, name: "set with other value", env: "agentless", want: true},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.shouldSetEnv {
				t.Setenv(IsAgentlessEnvName, tc.env)
			}
			assert.Equal(t, tc.want, IsAgentless())
		})
	}
}
