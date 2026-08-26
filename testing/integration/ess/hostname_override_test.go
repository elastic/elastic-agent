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

	"github.com/gofrs/uuid/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-libs/kibana"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/pkg/component"
	"github.com/elastic/elastic-agent/pkg/control/v2/cproto"
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
		// Linux-only: systemd drop-ins are Linux-specific. Container and standalone
		// deployments set ELASTIC_AGENT_HOSTNAME directly; see TestGetHostNameEnvOverride.
		OS: []define.OS{
			{Type: define.Linux},
		},
		Stack: &define.Stack{},
		Local: false,
		Sudo:  true,
	})

	cases := []struct {
		name    string
		runtime component.RuntimeManager
	}{
		{name: "process_runtime", runtime: component.ProcessRuntimeManager},
		{name: "otel_receiver", runtime: component.OtelRuntimeManager},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			agentFixture, err := define.NewFixtureFromLocalBuild(t, define.Version())
			require.NoError(t, err)

			ctx, cancel := testcontext.WithDeadline(t, t.Context(), time.Now().Add(20*time.Minute))
			defer cancel()

			installOpts := atesting.InstallOpts{
				NonInteractive: true,
				Force:          true,
			}

			customHostname := fmt.Sprintf("custom-node-%s", randStr(6))

			// Inject ELASTIC_AGENT_HOSTNAME via a systemd drop-in before the service starts.
			// The drop-in must exist before install because the service starts immediately on install.
			dropInDir := serviceDropInDir(installOpts.Namespace)
			dropInFile := filepath.Join(dropInDir, "elastic-agent-hostname.conf")
			dirCreated := false
			if _, err := os.Stat(dropInDir); os.IsNotExist(err) {
				require.NoError(t, os.MkdirAll(dropInDir, 0o755))
				dirCreated = true
			}
			// Preserve an existing drop-in file so cleanup can restore it.
			existingDropIn, readErr := os.ReadFile(dropInFile)
			require.NoError(t, os.WriteFile(dropInFile, []byte(fmt.Sprintf("[Service]\nEnvironment=ELASTIC_AGENT_HOSTNAME=%s\n", customHostname)), 0o644))
			t.Cleanup(func() {
				if readErr == nil {
					// Restore the original content.
					os.WriteFile(dropInFile, existingDropIn, 0o644) //nolint:gosec // G703: path is a fixed system drop-in location
				} else {
					os.Remove(dropInFile)
				}
				if dirCreated {
					os.Remove(dropInDir)
				}
			})

			createPolicyReq := kibana.AgentPolicy{
				Name:      fmt.Sprintf("test-policy-hostname-%s-%s", tc.name, customHostname),
				Namespace: info.Namespace,
				MonitoringEnabled: []kibana.MonitoringEnabledOption{
					kibana.MonitoringEnabledLogs,
					kibana.MonitoringEnabledMetrics,
				},
				Overrides: map[string]interface{}{
					"agent": map[string]interface{}{
						"internal": map[string]interface{}{
							"runtime": map[string]interface{}{
								"metricbeat": map[string]interface{}{
									"system/metrics": string(tc.runtime),
								},
							},
						},
					},
				},
			}

			require.NoError(t, fleettools.UpdateESOutputPreset(ctx, info.KibanaClient, fleettools.DefaultFleetOutputID, fleettools.OutputPresetLatency))
			since := time.Now().UTC().Format(time.RFC3339)
			policy, agentID, err := tools.InstallAgentWithPolicy(ctx, t, installOpts, agentFixture, info.KibanaClient, createPolicyReq)
			require.NoError(t, err)

			_, err = tools.InstallPackageFromDefaultFile(ctx, info.KibanaClient, "system",
				integration.PreinstalledPackages["system"], "testdata/system_integration_setup.json",
				uuid.Must(uuid.NewV4()).String(), policy.ID)
			require.NoError(t, err)

			t.Cleanup(func() {
				// context.Background is intentional: t.Context() is already cancelled when Cleanup runs.
				cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), time.Minute) //nolint:forbidigo // t.Context() is cancelled at cleanup time
				defer cleanupCancel()

				t.Log("Un-enrolling Elastic Agent...")
				assert.NoError(t, fleettools.UnEnrollAgent(cleanupCtx, info.KibanaClient, agentID))
			})

			t.Log("Verify that agent name in Fleet matches ELASTIC_AGENT_HOSTNAME")
			verifyAgentName(ctx, t, agentID, customHostname, info.KibanaClient)

			t.Log("Verify that the System integration is running on the expected runtime")
			assertComponentRuntime(ctx, t, agentFixture, "system/metrics-default", tc.runtime)

			t.Log("Verify that host.name in beats-collected system metrics matches ELASTIC_AGENT_HOSTNAME")
			verifyHostNameInIndices(t, "metrics-system.*-*", customHostname, since, info.Namespace, info.ESClient, 5*time.Minute)

			t.Log("Verify that host.name in logs-* and metrics-* matches ELASTIC_AGENT_HOSTNAME")
			verifyHostNameInIndices(t, "logs-*", customHostname, since, info.Namespace, info.ESClient, 5*time.Minute)
			verifyHostNameInIndices(t, "metrics-*", customHostname, since, info.Namespace, info.ESClient, 5*time.Minute)
		})
	}
}

func assertComponentRuntime(ctx context.Context, t *testing.T, fixture *atesting.Fixture, componentID string, runtime component.RuntimeManager) {
	t.Helper()
	want := componentVersionInfoNameForRuntime(runtime)
	require.EventuallyWithT(t, func(collect *assert.CollectT) {
		status, err := fixture.ExecStatus(ctx)
		assert.NoError(collect, err)

		var found bool
		for _, comp := range status.Components {
			if comp.ID == componentID && comp.VersionInfo.Name == want {
				compState := cproto.State(comp.State) //nolint:gosec // status values are guaranteed to be valid
				assert.Equal(collect, cproto.State_HEALTHY, compState,
					"expected component %q to be healthy, got %s", componentID, compState)
				found = true
				break
			}
		}
		assert.True(collect, found, "expected component %q to run as %q (runtime %s)", componentID, want, runtime)
	}, 2*time.Minute, 5*time.Second)
}
