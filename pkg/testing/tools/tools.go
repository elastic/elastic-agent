// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package tools

import (
	"testing"

	"github.com/elastic/elastic-agent-libs/kibana"
)

// WaitForAgentStatus returns a niladic function that returns true if the agent
// has reached expectedStatus; false otherwise. The returned function is intended
// for use with assert.Eventually or require.Eventually.
func WaitForAgentStatus(t *testing.T, client *kibana.Client, expectedStatus string) func() bool {
	return func() bool {
		currentStatus, err := GetAgentStatus(client)
		if err != nil {
			t.Errorf("unable to determine agent status: %s", err.Error())
			return false
		}

		if currentStatus == expectedStatus {
			return true
		}

		t.Logf("Agent status: %s", currentStatus)
		return false
	}
}
