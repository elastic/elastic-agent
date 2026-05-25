// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration

package ess

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httputil"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-libs/kibana"
	atesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/tools/fleettools"
	"github.com/elastic/elastic-agent/pkg/testing/tools/testcontext"
	"github.com/elastic/elastic-agent/testing/integration"
)

func TestLoggingFileConfigViaFleet(t *testing.T) {
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
		EnrollOpts: atesting.EnrollOpts{
			URL:             fleetServerURL,
			EnrollmentToken: enrollmentTokenResp.APIKey,
		},
	})
	assert.NoErrorf(t, err, "Error installing agent. Install output:\n%s\n", string(installOutput))

	require.Eventuallyf(t, func() bool {
		return waitForAgentAndFleetHealthy(ctx, t, f)
	}, 2*time.Minute, 5*time.Second, "agent never became healthy before logging policy change")

	logGlob := filepath.Join(
		f.WorkDir(), "data", "elastic-agent-*", "logs", "*.ndjson",
	)

	t.Log("Applying policy override: agent.logging.to_files=false, agent.logging.to_stderr=true")
	applyMainLoggingOutputPolicy(t, info, policyResp.AgentPolicy, true, false)

	require.Eventuallyf(t, func() bool {
		return waitForAgentAndFleetHealthy(ctx, t, f)
	}, 5*time.Minute, 5*time.Second,
		"agent never became healthy after logging config policy change")
	t.Log("Agent is healthy after the initial re-exec — starting loop observation")

	logFilesAfter, globErr := filepath.Glob(logGlob)
	require.NoError(t, globErr, "globbing log files after policy change")
	t.Logf("Agent log files present on disk after to_files=false: %v", logFilesAfter)
}

func applyMainLoggingOutputPolicy(t *testing.T, info *define.Info, policy kibana.AgentPolicy, toStderr, toFiles bool) {
	t.Helper()

	body := fmt.Sprintf(`
{
  "name": %q,
  "namespace": %q,
  "overrides": {
    "agent": {
      "logging": {
        "to_stderr": %v,
        "to_files":  %v
      }
    }
  }
}`, policy.Name, policy.Namespace, toStderr, toFiles)

	sendPolicyUpdate(t, info, policy.ID, body)
}

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
	customLogDir := filepath.Join("/tmp", "ea-test-logs-"+uuid.Must(uuid.NewV4()).String())
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
}

// applyLoggingFilePathPolicy overrides agent.logging.files.path in the Fleet policy.
// to_files is left at its default (true) so the agent continues writing to disk.
func applyLoggingFilePathPolicy(t *testing.T, info *define.Info, policy kibana.AgentPolicy, logPath string) {
	t.Helper()

	body := fmt.Sprintf(`
{
  "name": %q,
  "namespace": %q,
  "overrides": {
    "agent": {
      "logging": {
        "files": {
          "path": %q
        }
      }
    }
  }
}`, policy.Name, policy.Namespace, logPath)

	sendPolicyUpdate(t, info, policy.ID, body)
}

func sendPolicyUpdate(t *testing.T, info *define.Info, policyID, body string) {
	t.Helper()

	resp, err := info.KibanaClient.Send(
		http.MethodPut,
		fmt.Sprintf("/api/fleet/agent_policies/%s", policyID),
		nil,
		nil,
		bytes.NewBufferString(body),
	)
	if err != nil {
		t.Fatalf("could not execute request to Kibana/Fleet: %s", err)
	}
	if resp.StatusCode != http.StatusOK {
		respDump, dumpErr := httputil.DumpResponse(resp, true)
		if dumpErr != nil {
			t.Fatalf("could not dump Kibana error response: %s", dumpErr)
		}
		t.Log("Kibana error response:")
		t.Log(string(respDump))
		t.Fatalf("received non-200 status when updating Fleet policy: %d", resp.StatusCode)
	}
}
