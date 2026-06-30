// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration

package ess

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/tools/testcontext"
	"github.com/elastic/elastic-agent/testing/integration"
)

// minimalStandaloneConfig is a valid standalone config with no inputs and
// monitoring disabled. The shipped default has agent.logging.to_stderr: true
// which is the setting that --path.logs must override.
const minimalStandaloneConfig = `
outputs:
  default:
    type: elasticsearch
    hosts: ["%s"]
    preset: latency
    api_key: "fake-key"

agent.monitoring:
  enabled: false
  logs: false
  metrics: false

agent.logging.to_stderr: true
`

// TestRunWithCustomLogsPath verifies that passing --path.logs to
// elastic-agent run causes the agent to write logs to the user-specified
// directory, even when the config has agent.logging.to_stderr: true.
// It also verifies that the internal log (consumed by diagnostics) is still
// written to path.home.
// See https://github.com/elastic/elastic-agent/issues/13320
func TestRunWithCustomLogsPath(t *testing.T) {
	_ = define.Require(t, define.Requirements{
		Group: integration.Default,
		Stack: &define.Stack{},
		Local: true,
		Sudo:  false,
	})

	ctx, cancel := testcontext.WithTimeout(
		t,
		t.Context(),
		5*time.Minute,
	)
	defer cancel()

	agentFixture, err := define.NewFixtureFromLocalBuild(t, define.Version())
	require.NoError(t, err)

	// A mock ES gives the agent a valid output target so it starts cleanly.
	esURL := integration.StartMockES(t, 0, 0, 0, 0)

	cfg := []byte(strings.ReplaceAll(minimalStandaloneConfig, "%s", esURL.String()))

	require.NoError(t, agentFixture.Prepare(ctx))
	require.NoError(t, agentFixture.Configure(ctx, cfg))

	customLogsDir := t.TempDir()

	cmd, err := agentFixture.PrepareAgentCommand(ctx, []string{
		"run",
		"--path.logs", customLogsDir,
	})
	require.NoError(t, err)

	agentOutput := strings.Builder{}
	cmd.Stderr = &agentOutput
	cmd.Stdout = &agentOutput

	t.Cleanup(func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
		}
		if t.Failed() {
			t.Log("Elastic-Agent output:")
			t.Log(agentOutput.String())
		}
	})

	require.NoError(t, cmd.Start())

	// The user-facing log must appear in the custom --path.logs directory.
	requireLogFileInDir(t, customLogsDir, "user log under --path.logs")

	// The internal log (for diagnostics) must still be written to
	// path.home regardless of --path.logs.
	internalLogsGlob := filepath.Join(
		agentFixture.WorkDir(),
		"data", "elastic-agent-*", "logs", "elastic-agent*")
	requireLogFileInDir(t, internalLogsGlob, "internal log under path.home")
}

// requireLogFileInDir polls until at least one non-empty log file is found
// matching globPattern (or directly inside dir if globPattern is a plain dir).
func requireLogFileInDir(t *testing.T, globOrDir, desc string) {
	t.Helper()

	pattern := globOrDir
	if info, err := os.Stat(globOrDir); err == nil && info.IsDir() {
		pattern = filepath.Join(globOrDir, "elastic-agent*")
	}

	require.Eventuallyf(t, func() bool {
		files, err := filepath.Glob(pattern)
		if err != nil || len(files) == 0 {
			return false
		}
		// Require at least one file to have content so we know logging started.
		for _, f := range files {
			if info, err := os.Stat(f); err == nil && info.Size() > 0 {
				return true
			}
		}
		return false
	}, time.Minute, time.Second,
		"%s: no non-empty log file found matching %s", desc, pattern)
}
