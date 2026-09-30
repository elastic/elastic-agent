// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration

package ess

import (
	"context"
	"os/exec"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	atesting "github.com/elastic/elastic-agent/pkg/testing"
)

const (
	agentLogDirectory                 = "/var/log/elastic-agent"
	periodicRollbackCleanupStartupLog = "starting periodically cleaning rollbacks"
)

func assertPeriodicRollbackCleanupNotStarted(t *testing.T, ctx context.Context, fixture *atesting.Fixture) {
	t.Helper()

	out, err := exec.CommandContext(ctx, "sudo", "systemctl", "stop", "elastic-agent").CombinedOutput()
	require.NoError(t, err, "failed to stop elastic-agent: %s", out)

	out, err = exec.CommandContext(ctx, "sudo", "find", agentLogDirectory, "-type", "f", "-delete").CombinedOutput()
	require.NoError(t, err, "failed to clear Elastic Agent logs: %s", out)

	out, err = exec.CommandContext(ctx, "sudo", "systemctl", "start", "elastic-agent").CombinedOutput()
	require.NoError(t, err, "failed to start elastic-agent: %s", out)

	var healthErr error
	require.Eventuallyf(t, func() bool {
		healthErr = fixture.IsHealthyOrDegradedFromOutput(ctx)
		return healthErr == nil
	}, 5*time.Minute, time.Second, "Elastic-Agent did not report healthy after restart: %v", healthErr)

	logs, err := exec.CommandContext(
		ctx,
		"sudo",
		"find",
		agentLogDirectory,
		"-type",
		"f",
		"-name",
		"elastic-agent-*.ndjson",
		"-exec",
		"cat",
		"{}",
		"+",
	).CombinedOutput()
	require.NoError(t, err, "failed to read Elastic Agent logs: %s", logs)
	require.NotEmpty(t, logs, "Elastic Agent did not write an agent log after restart")
	require.NotContains(t, string(logs), periodicRollbackCleanupStartupLog,
		"periodic rollback cleanup started for an unupgradable Elastic Agent")
}
