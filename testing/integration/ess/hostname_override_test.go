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
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	atesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/tools"
	"github.com/elastic/elastic-agent/pkg/testing/tools/fleettools"
	"github.com/elastic/elastic-agent/pkg/testing/tools/testcontext"
	"github.com/elastic/elastic-agent/testing/integration"
)

// serviceDropInDir returns the path of the systemd drop-in directory for the given service namespace.
func serviceDropInDir(namespace string) string {
	return fmt.Sprintf("/etc/systemd/system/%s.service.d", paths.ServiceNameForNamespace(namespace))
}

func TestHostnameEnvOverride(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Group: integration.Hostname,
		// Linux-only: the env-injection mechanism (systemd drop-in) is Linux-specific.
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

	// Inject ELASTIC_AGENT_HOSTNAME via a systemd drop-in before the service starts.
	// Drop-ins are the standard, distro-agnostic way to override systemd unit settings;
	// this is equivalent to what `systemctl edit elastic-agent` would produce.
	// The drop-in must exist before install because the service starts immediately on install.
	dropInDir := serviceDropInDir(installOpts.Namespace)
	dropInFile := filepath.Join(dropInDir, "elastic-agent-hostname.conf")
	require.NoError(t, os.MkdirAll(dropInDir, 0o755))
	require.NoError(t, os.WriteFile(dropInFile, []byte(fmt.Sprintf("[Service]\nEnvironment=ELASTIC_AGENT_HOSTNAME=%s\n", customHostname)), 0o644))
	t.Cleanup(func() { os.RemoveAll(dropInDir) })

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
