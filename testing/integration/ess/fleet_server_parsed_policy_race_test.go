// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration

package ess

// TestFleetServerParsedPolicyRaceConditionFix is a regression test for
// elastic/fleet-server#7794.
//
// It verifies that fleet-server correctly serves a policy with a
// remote_elasticsearch output whose service_token is stored as a Fleet secret
// (non-empty secret_references) without crashing.
//
// The service_token must be wrapped in {"secrets": {"service_token": "..."}} when
// creating the Fleet output — NOT passed as a top-level field — so that Fleet
// stores it as a secret and populates secret_references in the generated policy.
//
// Elastic Defend is also installed to make the test more realistic and cover
// an edge case with additional policy complexity.

import (
	"archive/zip"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-libs/kibana"
	"github.com/elastic/elastic-agent-libs/testing/estools"
	atesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/tools"
	"github.com/elastic/elastic-agent/pkg/testing/tools/check"
	"github.com/elastic/elastic-agent/pkg/testing/tools/fleettools"
	"github.com/elastic/elastic-agent/pkg/testing/tools/testcontext"
	"github.com/elastic/elastic-agent/testing/integration"
)

func TestFleetServerParsedPolicyRaceConditionFix(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Group: integration.Fleet,
		Stack: &define.Stack{},
		Sudo:  true,
		Local: false,
		OS: []define.OS{
			{Type: define.Linux},
		},
	})

	ctx, cancel := testcontext.WithDeadline(t, t.Context(), time.Now().Add(15*time.Minute))
	defer cancel()

	// Create a service token. The token is stored as a Fleet secret (via the
	// "secrets" wrapper) so that secret_references is populated in the policy —
	// the precondition for the race.
	t.Log("Creating service token for remote_elasticsearch output...")
	serviceToken, err := estools.CreateServiceToken(ctx, info.ESClient, "fleet-server")
	require.NoError(t, err, "failed to create service token")

	// Use the same ES cluster as the remote target; a separate cluster is not
	// needed to reproduce or verify the fix.
	esHost, ok := os.LookupEnv("ELASTICSEARCH_HOST")
	require.True(t, ok, "ELASTICSEARCH_HOST must be set")

	// Create the remote_elasticsearch Fleet output. The service_token is wrapped
	// in {"secrets": {...}} so that Fleet stores it as a secret and adds an entry
	// to secret_references in the generated policy.
	t.Log("Creating remote_elasticsearch Fleet output with secrets...")
	outputID := createRemoteESOutputWithSecret(t, ctx, info, esHost, serviceToken)
	t.Logf("Created remote_elasticsearch output with ID: %s", outputID)

	// Create the agent policy, pointing its elasticsearch output to the remote ES cluster.
	// Any policy that references this output will have non-empty secret_references.
	policyUUID := uuid.Must(uuid.NewV4()).String()
	policyReq := kibana.AgentPolicy{
		Name:        "test-fleet-server-race-fix-" + policyUUID,
		Namespace:   info.Namespace,
		Description: "Regression test: fleet-server PR #7794",
		MonitoringEnabled: []kibana.MonitoringEnabledOption{
			kibana.MonitoringEnabledLogs,
			kibana.MonitoringEnabledMetrics,
		},
		DataOutputID: outputID,
	}

	t.Log("Creating agent policy...")
	policyResp, err := info.KibanaClient.CreatePolicy(ctx, policyReq)
	require.NoError(t, err, "failed to create agent policy")
	t.Logf("Created policy %s (ID: %s, revision: %d)", policyResp.Name, policyResp.ID, policyResp.Revision)

	// Add the Elastic Defend integration to the policy.
	t.Log("Installing Elastic Defend package policy...")
	_, err = installElasticDefendPackage(t, info, policyResp.ID)
	require.NoError(t, err, "failed to install Elastic Defend package policy")

	// Fetch the updated policy revision after adding the package.
	updatedPolicy, err := info.KibanaClient.GetPolicy(ctx, policyResp.ID)
	require.NoError(t, err, "failed to fetch updated policy")
	t.Logf("Policy revision after adding Elastic Defend: %d", updatedPolicy.Revision)

	// Prepare and install the Elastic Agent.
	fixture, err := define.NewFixtureFromLocalBuild(t, define.Version())
	require.NoError(t, err)
	err = fixture.Prepare(ctx)
	require.NoError(t, err)

	installOpts := atesting.InstallOpts{
		NonInteractive: true,
		Force:          true,
		Privileged:     true,
	}

	t.Log("Enrolling Elastic Agent...")
	agentID, err := tools.InstallAgentForPolicy(ctx, t, installOpts, fixture, info.KibanaClient, policyResp.ID)
	require.NoError(t, err, "failed to install and enroll agent")
	t.Logf("Enrolled agent with ID: %s", agentID)

	t.Cleanup(func() {
		//nolint:forbidigo // t.Context() is cancelled by cleanup time
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), time.Minute)
		defer cleanupCancel()
		if err := fleettools.UnEnrollAgent(cleanupCtx, info.KibanaClient, agentID); err != nil {
			t.Logf("warning: failed to unenroll agent %s: %v", agentID, err)
		}
	})

	// Verify the agent is connected to Fleet.
	t.Log("Verifying agent is connected to Fleet (no panic)...")
	require.True(t, check.ConnectedToFleet(ctx, t, fixture, 5*time.Minute),
		"agent did not connect to Fleet — fleet-server may have crashed with index-out-of-range panic")

	// Run elastic-agent diagnostics and verify:
	//   1. The command exits without error.
	//   2. The archive contains no panic strings.
	t.Log("Running elastic-agent diagnostics...")
	diagZip, err := fixture.ExecDiagnostics(ctx)
	require.NoError(t, err, "diagnostics command should exit without error; "+
		"a non-zero exit may indicate a crash or panic in the agent or fleet-server")

	t.Cleanup(func() {
		if err := os.Remove(diagZip); err != nil && !os.IsNotExist(err) {
			t.Logf("warning: failed to remove diagnostics archive %s: %v", diagZip, err)
		}
	})

	t.Log("Checking diagnostics archive for panic strings...")
	checkDiagArchiveNoPanic(t, diagZip)

	// Verify the agent's applied policy revision in Fleet matches (or exceeds) the latest revision.
	t.Log("Verifying agent policy revision matches Fleet...")
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		currentPolicy, err := info.KibanaClient.GetPolicy(ctx, policyResp.ID)
		if !assert.NoError(c, err, "failed to get policy from Fleet") {
			return
		}
		agent, err := info.KibanaClient.GetAgent(ctx, kibana.GetAgentRequest{ID: agentID})
		if !assert.NoError(c, err, "failed to get agent from Fleet") {
			return
		}
		assert.GreaterOrEqual(c, agent.PolicyRevision, currentPolicy.Revision,
			"agent policy revision (%d) should match Fleet policy revision (%d); "+
				"a panic mid-dispatch could leave the agent on an older revision",
			agent.PolicyRevision, currentPolicy.Revision)
	}, 5*time.Minute, 5*time.Second, "agent policy revision did not match Fleet's within timeout")
}

// createRemoteESOutputWithSecret creates a Fleet output of type remote_elasticsearch
// with the service_token stored as a Fleet secret (using the "secrets" wrapper).
// This is the trigger condition for secret_references to be non-empty in the policy.
// Returns the created output ID.
func createRemoteESOutputWithSecret(t *testing.T, ctx context.Context, info *define.Info, esHost, serviceToken string) string {
	t.Helper()

	// Replace hyphens with underscores: the Fleet outputs API rejects IDs that
	// contain UUID-formatted strings (consecutive hyphens).
	outputName := "remote-es-" + strings.ReplaceAll(uuid.Must(uuid.NewV4()).String(), "-", "_")

	body := map[string]any{
		"name":  outputName,
		"type":  "remote_elasticsearch",
		"hosts": []string{esHost},
		// Using "secrets" wrapper (NOT top-level "service_token") causes Fleet to
		// store the token as a Fleet secret, which populates secret_references in
		// the generated policy — the precondition for the fleet-server race bug.
		"secrets": map[string]any{
			"service_token": serviceToken,
		},
	}

	bodyBytes, err := json.Marshal(body)
	require.NoError(t, err, "failed to marshal remote_elasticsearch output body")

	status, result, err := info.KibanaClient.Request(
		http.MethodPost,
		"/api/fleet/outputs",
		nil,
		nil,
		strings.NewReader(string(bodyBytes)),
	)
	require.NoError(t, err, "failed to call Fleet outputs API")
	require.Equal(t, http.StatusOK, status,
		"Fleet outputs API returned unexpected status %d; body: %s", status, string(result))

	var outputResp struct {
		Item struct {
			ID string `json:"id"`
		} `json:"item"`
	}
	require.NoError(t, json.Unmarshal(result, &outputResp),
		"failed to decode Fleet outputs API response: %s", string(result))
	require.NotEmpty(t, outputResp.Item.ID, "Fleet outputs API returned empty output ID")

	t.Logf("Created Fleet output: %s (ID: %s)", outputName, outputResp.Item.ID)

	t.Cleanup(func() {
		//nolint:forbidigo // t.Context() is cancelled by cleanup time
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		deleteStatus, deleteResult, deleteErr := info.KibanaClient.Request(
			http.MethodDelete,
			fmt.Sprintf("/api/fleet/outputs/%s", outputResp.Item.ID),
			nil,
			nil,
			nil,
		)
		if deleteErr != nil || deleteStatus != http.StatusOK {
			t.Logf("warning: failed to delete Fleet output %s (status %d): %v %s",
				outputResp.Item.ID, deleteStatus, deleteErr, string(deleteResult))
		}
		_ = cleanupCtx
	})

	return outputResp.Item.ID
}

// checkDiagArchiveNoPanic opens the diagnostics ZIP and searches every text
// entry for "index out of range" and "panic: runtime" strings. If either is
// found, the test is failed with context about the offending file.
func checkDiagArchiveNoPanic(t *testing.T, diagZip string) {
	t.Helper()

	zr, err := zip.OpenReader(diagZip)
	require.NoError(t, err, "failed to open diagnostics archive %s", diagZip)
	defer zr.Close()

	panicSignatures := []string{
		"index out of range",
		"panic: runtime",
	}

	for _, f := range zr.File {
		// Skip binary and pprof entries — they won't contain text panics.
		if strings.HasSuffix(f.Name, ".pprof.gz") ||
			strings.HasSuffix(f.Name, ".profile.gz") ||
			strings.HasSuffix(f.Name, ".tar.gz") ||
			strings.HasSuffix(f.Name, ".zip") {
			continue
		}

		rc, err := f.Open()
		if err != nil {
			t.Logf("warning: skipping %s (open error: %v)", f.Name, err)
			continue
		}

		buf := make([]byte, 0, f.UncompressedSize64)
		readBuf := make([]byte, 4096)
		for {
			n, readErr := rc.Read(readBuf)
			if n > 0 {
				buf = append(buf, readBuf[:n]...)
			}
			if readErr != nil {
				break
			}
		}
		rc.Close()

		content := string(buf)
		for _, sig := range panicSignatures {
			assert.NotContains(t, content, sig,
				"diagnostics archive entry %q contains panic signature %q — "+
					"fleet-server or elastic-agent may have panicked with the "+
					"concurrent slice-mutation bug (fleet-server#7794)", f.Name, sig)
		}
	}
}
