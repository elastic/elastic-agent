// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.
//go:build integration

package ess

import (
	"bytes"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	aTesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/tools/testcontext"
	"github.com/elastic/elastic-agent/testing/integration"
)

// TestAgentStartShutdown verifies that the plain elastic-agent run command
// starts up and then shuts down gracefully when sent a console-control
// signal via fixture.Stop.
func TestAgentStartShutdown(t *testing.T) {
	define.Require(t, define.Requirements{
		Group: integration.Default,
		Local: true,
	})

	output := &bytes.Buffer{}
	fixture, err := define.NewFixtureFromLocalBuild(t, define.Version(),
		aTesting.WithCmdOutput(output))
	require.NoError(t, err)

	ctx, cancel := testcontext.WithDeadline(t, t.Context(), time.Now().Add(10*time.Minute))
	defer cancel()
	err = fixture.Prepare(ctx, fakeComponent)
	require.NoError(t, err)

	// set logging level to debug so we see the log message we want
	var config = `
agent:
  logging:
    level: debug
outputs:
  default:
    type: fake-output
inputs:
  - id: fake
    type: fake
    state: 2
    message: Healthy
`

	require.NoError(t, fixture.Configure(ctx, []byte(config)))
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		assert.NoError(t, fixture.Run(ctx))
	}()

	t.Cleanup(func() {
		if t.Failed() {
			t.Log("Elastic Agent output:")
			t.Log(output.String())
		}
	})

	require.EventuallyWithT(t, func(collect *assert.CollectT) {
		assert.Contains(collect, output.String(), "Registered signal handlers")
	}, 30*time.Second, time.Second)

	fixture.Stop()
	wg.Wait()

	// Poll briefly: process.Info.Wait (used by fixture.Run) returns as soon
	// as the agent process exits and does not synchronize with the exec.Cmd
	// stdio goroutines, so the last few log lines may still be in the kernel
	// pipe buffer when wg.Wait returns. Same caveat as TestOtelStartShutdown.
	// TODO: Make process.Info.Wait synchronize this correctly
	require.EventuallyWithT(t, func(collect *assert.CollectT) {
		assert.Contains(collect, output.String(), "Shutting down completed.")
	}, 5*time.Second, 100*time.Millisecond)
}
