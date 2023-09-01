// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package tools

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/elastic/elastic-agent/pkg/control/v2/client"
	"github.com/elastic/elastic-agent/pkg/control/v2/cproto"
)

// WaitForLocalAgentHealthy will keep checking the agent state until it becomes healthy
// ot the timeout is exceeded. If the agent becomes health, it returns true, if
// not the test is marked as failed and false is returned.
// The timeout is the context deadline, if defined, or set to 2 minutes.
func WaitForLocalAgentHealthy(ctx context.Context, t *testing.T, c client.Client) bool {
	// https://github.com/elastic/elastic-agent/pull/3265
	timeout := 2 * time.Minute
	if deadline, ok := ctx.Deadline(); ok {
		timeout = time.Until(deadline)
	}

	return assert.Eventually(t, func() bool {
		err := c.Connect(ctx)
		if err != nil {
			t.Logf("connecting client to agent: %v", err)
			return false
		}
		defer c.Disconnect()
		state, err := c.State(ctx)
		if err != nil {
			t.Logf("error getting the agent state: %v", err)
			return false
		}
		t.Logf("agent state: %+v", state)
		return state.State == cproto.State_HEALTHY
	}, timeout, 10*time.Second, "Agent never became healthy")
}
