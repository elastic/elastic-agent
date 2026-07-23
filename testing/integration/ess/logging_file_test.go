// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration

package ess

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-libs/kibana"
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
		Group: integration.Fleet,
		Stack: &define.Stack{},
		Local: true,
		Sudo:  false,
		OS: []define.OS{
			{Type: define.Linux},
		},
	})

	deadline := time.Now().Add(15 * time.Minute)
	ctx, cancel := testcontext.WithDeadline(t, t.Context(), deadline)
	defer cancel()

	f, err := define.NewFixtureFromLocalBuild(t, define.Version())
	require.NoError(t, err, "failed creating agent fixture")

	policyResp, enrollmentTokenResp := createPolicyAndEnrollmentToken(
		ctx, t, info.KibanaClient, createBasicPolicy())
	t.Logf("Created policy %+v", policyResp.AgentPolicy)

	fleetServerURL, err := fleettools.DefaultURL(ctx, info.KibanaClient)
	require.NoError(t, err, "failed getting Fleet Server URL")

	enrollArgs := []string{
		"enroll",
		"--force",
		"--skip-daemon-reload",
		"--url",
		fleetServerURL,
		"--enrollment-token",
		enrollmentTokenResp.APIKey,
	}

	enrollCmd, err := f.PrepareAgentCommand(ctx, enrollArgs)
	if err != nil {
		t.Fatalf("could not prepare enroll command: %s", err)
	}
	if out, err := enrollCmd.CombinedOutput(); err != nil {
		t.Fatalf("error enrolling elastic-agent: %s\nOutput:\n%s", err, string(out))
	}

	err = f.Configure(ctx, []byte(fleetManagedAgentConfig))
	require.NoError(t, err)

	runAgentCmd, agentOutput := prepareAgentCMD(t, ctx, f, nil, nil)
	if err := runAgentCmd.Start(); err != nil {
		t.Fatalf("could not start elastic-agent: %s", err)
	}

	t.Cleanup(func() {
		if t.Failed() {
			t.Errorf("elastic-agent output:\n%s", agentOutput)
		}
	})

	require.Eventually(t, func() bool {
		return waitForAgentAndFleetHealthy(ctx, t, f)
	}, 2*time.Minute, 5*time.Second, "elastic-agent did not report healthy")

	// Create a custom directory that the agent can write to.
	customLogDir := filepath.Join(t.TempDir(), "logs")
	require.NoError(t, os.MkdirAll(customLogDir, 0o755), "create custom log directory")

	// Apply the logging path override and wait for the agent to pick it up.
	t.Logf("Applying policy override: agent.logging.files.path=%s", customLogDir)
	err = applyLoggingFilePathPolicy(ctx, info, policyResp.AgentPolicy, customLogDir)
	require.NoError(t, err)

	require.Eventually(t, func() bool {
		inspectOutput, inspectErr := f.ExecInspect(ctx)
		return inspectErr == nil && inspectOutput.Agent.Logging.Files.Path == customLogDir
	}, 2*time.Minute, time.Second, "elastic-agent did not apply the policy change")

	// The agent must create at least one log file in the new directory.
	require.Eventuallyf(t, func() bool {
		matches, _ := filepath.Glob(filepath.Join(customLogDir, "*.ndjson"))
		return len(matches) > 0
	}, 2*time.Minute, 5*time.Second,
		"no log files found in custom log directory %s after path change", customLogDir)
}

func applyLoggingFilePathPolicy(ctx context.Context, info *define.Info, policy kibana.AgentPolicy, logPath string) error {
	req := kibana.AgentPolicyUpdateRequest{
		Name:      policy.Name,
		Namespace: policy.Namespace,
		Overrides: map[string]any{
			"agent": map[string]any{
				"logging": map[string]any{
					"to_stderr": false,
					"to_files":  true,
					"files": map[string]any{
						"path": logPath,
					},
				},
			},
		},
	}
	_, err := info.KibanaClient.UpdatePolicy(ctx, policy.ID, req)
	return err
}
