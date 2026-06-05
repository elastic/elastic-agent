// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration

package ess

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-libs/kibana"
	atesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/tools/fleettools"
	"github.com/elastic/elastic-agent/pkg/testing/tools/testcontext"
	"github.com/elastic/elastic-agent/testing/integration"
)

// TestLoggingFilePathChangedViaFleet verifies that when agent.logging.files.path
// is updated via a Fleet policy override the agent re-execs once and subsequently
// writes its log files to the new location rather than the default one.
func TestLoggingFilePathChangedViaFleet(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Stack: &define.Stack{},
		Local: false,
		Sudo:  true,
		OS: []define.OS{
			{Type: define.Linux},
		},
		Group: integration.Default,
	})

	deadline := time.Now().Add(15 * time.Minute)
	ctx, cancel := testcontext.WithDeadline(t, context.Background(), deadline)
	defer cancel()

	f, err := define.NewFixtureFromLocalBuild(t, define.Version())
	require.NoError(t, err, "failed creating agent fixture")

	policyResp, enrollmentTokenResp := createPolicyAndEnrollmentToken(
		ctx, t, info.KibanaClient, createBasicPolicy())
	t.Logf("Created policy %+v", policyResp.AgentPolicy)

	fleetServerURL, err := fleettools.DefaultURL(ctx, info.KibanaClient)
	require.NoError(t, err, "failed getting Fleet Server URL")

	installOutput, err := f.Install(ctx, &atesting.InstallOpts{
		NonInteractive: true,
		Force:          true,
		Privileged:     true,
		EnrollOpts: atesting.EnrollOpts{
			URL:             fleetServerURL,
			EnrollmentToken: enrollmentTokenResp.APIKey,
		},
	})
	assert.NoErrorf(t, err, "Error installing agent. Install output:\n%s\n", string(installOutput))

	require.Eventuallyf(t, func() bool {
		return waitForAgentAndFleetHealthy(ctx, t, f)
	}, 2*time.Minute, 5*time.Second, "agent never became healthy before logging path change")

	// Create a custom directory that the agent (running as root) can write to.
	customLogDir := filepath.Join(t.TempDir(), "logs")
	require.NoError(t, os.MkdirAll(customLogDir, 0o755), "create custom log directory")
	t.Cleanup(func() { _ = os.RemoveAll(customLogDir) })

	t.Logf("Applying policy override: agent.logging.files.path=%s", customLogDir)
	applyLoggingFilePathPolicy(t, info, policyResp.AgentPolicy, customLogDir)

	// Wait for the agent to re-exec (due to Files config change) and recover.
	require.Eventuallyf(t, func() bool {
		return waitForAgentAndFleetHealthy(ctx, t, f)
	}, 5*time.Minute, 5*time.Second, "agent never became healthy after logging path change")

	// The agent must create at least one log file in the new directory.
	require.Eventuallyf(t, func() bool {
		matches, _ := filepath.Glob(filepath.Join(customLogDir, "*.ndjson"))
		return len(matches) > 0
	}, 2*time.Minute, 5*time.Second,
		"no log files found in custom log directory %s after path change", customLogDir)

	inspectOutput, err := f.ExecInspect(ctx)
	require.NoError(t, err, "failed to exec inspect after logging policy change")
	require.False(t, inspectOutput.Agent.Logging.ToStderr)
	require.True(t, inspectOutput.Agent.Logging.ToFiles)
	require.Equal(t, customLogDir, inspectOutput.Agent.Logging.Files.Path)
}

func applyLoggingFilePathPolicy(t *testing.T, info *define.Info, policy kibana.AgentPolicy, logPath string) {
	t.Helper()

	body := fmt.Sprintf(`
{
  "name": %q,
  "namespace": %q,
  "overrides": {
    "agent": {
      "logging": {
        "to_stderr": false,
        "to_files": true,
        "files": {
          "path": %q
        }
      }
    }
  }
}`, policy.Name, policy.Namespace, logPath)

	sendPolicyUpdate(t, info, policy.ID, body)
}
