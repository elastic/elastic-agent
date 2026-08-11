// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration

package ess

import (
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-libs/kibana"
	atesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/tools"
	"github.com/elastic/elastic-agent/testing/integration"
)

// TestPolicyChangeNotAcknowledgedOnStateStoreFail verifies the fix for
// https://github.com/elastic/elastic-agent/issues/15126.
//
// When the state store write fails during policy processing the agent must not
// ACK the action. Fleet will then re-deliver the action after the agent
// restarts, allowing recovery once the underlying problem (e.g. a full or
// read-only disk) is resolved.
func TestPolicyChangeNotAcknowledgedOnStateStoreFail(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Group: integration.Fleet,
		Stack: &define.Stack{},
		Local: false,
		Sudo:  true,
		OS: []define.OS{
			{Type: define.Linux},
		},
	})

	ctx := t.Context()

	fixture, err := define.NewFixtureFromLocalBuild(t, define.Version())
	require.NoError(t, err)

	createPolicyReq := kibana.AgentPolicy{
		Name:        fmt.Sprintf("test-policy-state-store-fail-%d", time.Now().UnixNano()),
		Namespace:   info.Namespace,
		Description: "test policy for state store failure no-ack",
		MonitoringEnabled: []kibana.MonitoringEnabledOption{
			kibana.MonitoringEnabledLogs,
			kibana.MonitoringEnabledMetrics,
		},
	}

	installOpts := atesting.InstallOpts{
		NonInteractive: true,
		Force:          true,
		Insecure:       true,
	}

	policy, agentID, err := tools.InstallAgentWithPolicy(ctx, t, installOpts, fixture, info.KibanaClient, createPolicyReq)
	require.NoError(t, err)
	t.Logf("enrolled agent %s with policy %s", agentID, policy.ID)

	t.Cleanup(func() {
		// context.TODO: cleanup runs after the test context is cancelled, so we
		// need an independent context here.
		cleanupCtx, cleanupCancel := context.WithTimeout(context.TODO(), time.Minute)
		defer cleanupCancel()
		_, err := info.KibanaClient.UnEnrollAgent(cleanupCtx, kibana.UnEnrollAgentRequest{ID: agentID, Revoke: true})
		assert.NoError(t, err, "failed to unenroll agent %s", agentID)
	})

	// Find the versioned data directory that contains state.enc.
	stateDirs, err := filepath.Glob(filepath.Join(fixture.AgentDataDir(), "data", "elastic-agent-*"))
	require.NoError(t, err)
	require.NotEmpty(t, stateDirs, "versioned agent data directory not found under %s", fixture.AgentDataDir())
	stateDir := stateDirs[len(stateDirs)-1]
	t.Logf("versioned state directory: %s", stateDir)

	initialAgent, err := info.KibanaClient.GetAgent(ctx, kibana.GetAgentRequest{ID: agentID})
	require.NoError(t, err)
	initialRevision := initialAgent.PolicyRevision
	t.Logf("initial policy revision: %d", initialRevision)

	// Block state store writes before triggering the policy change.
	// chattr +i makes the directory immutable so no new files can be created
	// in it even by root.
	out, err := exec.CommandContext(ctx, "chattr", "+i", stateDir).CombinedOutput()
	require.NoError(t, err, "failed to set immutable flag on state dir: %s", out)
	t.Cleanup(func() {
		if out, err := exec.CommandContext(context.TODO(), "chattr", "-i", stateDir).CombinedOutput(); err != nil {
			t.Logf("warning: failed to clear immutable flag on state dir: %v: %s", err, out)
		}
	})

	// Trigger a policy change from Fleet.
	updatePolicyReq := kibana.AgentPolicyUpdateRequest{
		Name:              policy.Name,
		Namespace:         info.Namespace,
		Description:       "test policy for state store failure no-ack - revision bump",
		MonitoringEnabled: createPolicyReq.MonitoringEnabled,
	}
	updatedPolicy, err := info.KibanaClient.UpdatePolicy(ctx, policy.ID, updatePolicyReq)
	require.NoError(t, err)
	targetRevision := updatedPolicy.Revision
	t.Logf("triggered policy update to revision %d", targetRevision)

	// The agent must not advance the policy revision while the state store is unwritable.
	require.Never(t,
		tools.IsMinPolicyRevision(ctx, t, info.KibanaClient, agentID, targetRevision),
		90*time.Second,
		10*time.Second,
		"policy was acknowledged despite state store write failure (expected revision to stay at %d)", initialRevision,
	)

	// Stop the agent while the state store is still read-only, mirroring the
	// real-world scenario where a disk problem causes the agent to shut down.
	out, err = exec.CommandContext(ctx, "sudo", "systemctl", "stop", "elastic-agent").CombinedOutput()
	require.NoError(t, err, "failed to stop elastic-agent: %s", out)

	// Confirm the revision is still at the initial value after the agent stops.
	stoppedAgent, err := info.KibanaClient.GetAgent(ctx, kibana.GetAgentRequest{ID: agentID})
	require.NoError(t, err)
	require.Equal(t, initialRevision, stoppedAgent.PolicyRevision,
		"policy revision advanced while state store was read-only")

	// Restore write access, then start the agent.
	out, err = exec.CommandContext(ctx, "chattr", "-i", stateDir).CombinedOutput()
	require.NoError(t, err, "failed to clear immutable flag on state dir: %s", out)

	out, err = exec.CommandContext(ctx, "sudo", "systemctl", "start", "elastic-agent").CombinedOutput()
	require.NoError(t, err, "failed to start elastic-agent: %s", out)

	// Fleet re-delivers; the agent must apply and acknowledge the policy.
	require.Eventually(t,
		tools.IsMinPolicyRevision(ctx, t, info.KibanaClient, agentID, targetRevision),
		8*time.Minute,
		10*time.Second,
		"agent did not reach policy revision %d after restart with write access restored", targetRevision,
	)
}
