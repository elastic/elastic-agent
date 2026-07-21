// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration

package ess

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-libs/kibana"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	atesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/tools"
	"github.com/elastic/elastic-agent/pkg/testing/tools/fleettools"
	"github.com/elastic/elastic-agent/pkg/testing/tools/testcontext"
	"github.com/elastic/elastic-agent/testing/integration"
)

// serviceEnvFilePath returns the systemd EnvironmentFile path for the given service namespace.
// The systemd unit uses EnvironmentFile=-/etc/sysconfig/<service-name>, so env vars written
// here are injected into the service process before it starts.
func serviceEnvFilePath(namespace string) string {
	return fmt.Sprintf("/etc/sysconfig/%s", paths.ServiceNameForNamespace(namespace))
}

func TestHostnameEnvOverride(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Group: integration.Hostname,
		// Linux-only: the env-injection mechanism (systemd EnvironmentFile) is Linux-specific.
		// Non-service deployments (containers, standalone binary) inherit ELASTIC_AGENT_HOSTNAME
		// directly from their process environment; that path is covered by TestGetHostNameEnvOverride.
		OS: []define.OS{
			{Type: define.Linux},
		},
		Stack: &define.Stack{},
		Local: false,
		Sudo:  true,
	})

	agentFixture, err := define.NewFixtureFromLocalBuild(t, define.Version())
	require.NoError(t, err)

	ctx, cancel := testcontext.WithDeadline(t, t.Context(), time.Now().Add(10*time.Minute))
	defer cancel()

	installOpts := atesting.InstallOpts{
		NonInteractive: true,
		Force:          true,
	}

	customHostname := fmt.Sprintf("custom-node-%s", randStr(6))

	// Write ELASTIC_AGENT_HOSTNAME into the systemd EnvironmentFile before the service starts.
	// The file must exist before install because the service is started immediately on install.
	envFilePath := serviceEnvFilePath(installOpts.Namespace)
	require.NoError(t, os.WriteFile(envFilePath, []byte(fmt.Sprintf("ELASTIC_AGENT_HOSTNAME=%s\n", customHostname)), 0o644))
	t.Cleanup(func() { os.Remove(envFilePath) })

	createPolicyReq := kibana.AgentPolicy{
		Name:      "test-policy-hostname-override-" + customHostname,
		Namespace: info.Namespace,
		MonitoringEnabled: []kibana.MonitoringEnabledOption{
			kibana.MonitoringEnabledLogs,
			kibana.MonitoringEnabledMetrics,
		},
	}

	require.NoError(t, fleettools.UpdateESOutputPreset(ctx, info.KibanaClient, fleettools.DefaultFleetOutputID, fleettools.OutputPresetLatency))
	since := time.Now().UTC().Format(time.RFC3339)
	_, agentID, err := tools.InstallAgentWithPolicy(ctx, t, installOpts, agentFixture, info.KibanaClient, createPolicyReq)
	require.NoError(t, err)

	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(t.Context(), time.Minute)
		defer cleanupCancel()

		t.Log("Un-enrolling Elastic Agent...")
		assert.NoError(t, fleettools.UnEnrollAgent(cleanupCtx, info.KibanaClient, agentID))
	})

	t.Log("Verify that agent name in Fleet matches ELASTIC_AGENT_HOSTNAME")
	verifyAgentName(ctx, t, agentID, customHostname, info.KibanaClient)

	t.Log("Verify that host.name in logs-* and metrics-* matches ELASTIC_AGENT_HOSTNAME")
	verifyHostNameInIndices(t, "logs-*", customHostname, since, info.Namespace, info.ESClient)
	verifyHostNameInIndices(t, "metrics-*", customHostname, since, info.Namespace, info.ESClient)
}
