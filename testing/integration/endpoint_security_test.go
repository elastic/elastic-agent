// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build integration

package integration

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"text/template"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/google/uuid"

	"github.com/elastic/elastic-agent-libs/kibana"
	"github.com/elastic/elastic-agent/pkg/control/v2/client"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/tools"
)

const (
	// TODO: Setup a GitHub Action to update this for each release of https://github.com/elastic/endpoint-package
	endpointPackageVersion       = "8.9.0"
	endpointHealthPollingTimeout = 2 * time.Minute
)

//go:embed endpoint_security_package.json.tmpl
var endpointPackagePolicyTemplate string

type endpointPackageTemplateVars struct {
	ID       string
	Name     string
	PolicyID string
	Version  string
}

// Tests that the agent can install and uninstall the endpoint-security service while remaining
// healthy.
//
// Installing endpoint-security requires a Fleet managed agent with the Elastic Defend integration
// installed. The endpoint-security service is uninstalled when the agent is uninstalled.
//
// The agent is automatically uninstalled as part of test cleanup when installed with
// fixture.Install via tools.InstallAgentWithPolicy. Failure to uninstall the agent will fail the
// test automatically.
func TestInstallAndCLIUninstallWithEndpointSecurity(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Stack:   &define.Stack{},
		Local:   false, // requires Agent installation
		Isolate: false,
		Sudo:    true, // requires Agent installation
	})

	// Get path to agent executable.
	fixture, err := define.NewFixture(t, define.Version())
	require.NoError(t, err)

	t.Log("Enrolling the agent in Fleet")
	policyUUID := uuid.New().String()
	createPolicyReq := kibana.AgentPolicy{
		Name:        "test-policy-" + policyUUID,
		Namespace:   "default",
		Description: "Test policy " + policyUUID,
		MonitoringEnabled: []kibana.MonitoringEnabledOption{
			kibana.MonitoringEnabledLogs,
			kibana.MonitoringEnabledMetrics,
		},
	}
	policyResp, err := tools.InstallAgentWithPolicy(t, fixture, info.KibanaClient, createPolicyReq)

	t.Log("Installing Elastic Defend")
	installElasticDefendPackage(t, info, policyResp.ID)

	t.Log("Polling for endpoint-security to become Healthy")
	ctx, cancel := context.WithTimeout(context.Background(), endpointHealthPollingTimeout)
	defer cancel()

	agentClient := fixture.Client()
	err = agentClient.Connect(ctx)
	require.NoError(t, err)

	require.Eventually(t,
		func() bool { return agentAndEndpointAreHealthy(t, ctx, agentClient) },
		endpointHealthPollingTimeout,
		time.Second,
		"Endpoint component or units are not healthy.",
	)
	t.Log("Verified endpoint component and units are healthy")
}

// Tests that the agent can install and uninstall the endpoint-security service while remaining
// healthy. In this case endpoint-security is uninstalled because the agent was unenrolled, which
// triggers the creation of an empty agent policy removing all inputs (only when not force
// unenrolling). The empty agent policy triggers the uninstall of endpoint because endpoint was
// removed from the policy.
//
// Like the CLI uninstall test, the agent is uninstalled from the command line at the end of the test
// but at this point endpoint is already uninstalled at this point.
func TestInstallAndUnenrollWithEndpointSecurity(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Stack:   &define.Stack{},
		Local:   false, // requires Agent installation
		Isolate: false,
		Sudo:    true, // requires Agent installation
		OS: []define.OS{
			define.OS{Type: define.Linux, Arch: define.AMD64},
		},
	})

	// Get path to agent executable.
	fixture, err := define.NewFixture(t, define.Version())
	require.NoError(t, err)

	t.Log("Enrolling the agent in Fleet")
	policyUUID := uuid.New().String()
	createPolicyReq := kibana.AgentPolicy{
		Name:        "test-policy-" + policyUUID,
		Namespace:   "default",
		Description: "Test policy " + policyUUID,
		MonitoringEnabled: []kibana.MonitoringEnabledOption{
			kibana.MonitoringEnabledLogs,
			kibana.MonitoringEnabledMetrics,
		},
	}
	policyResp, err := tools.InstallAgentWithPolicy(t, fixture, info.KibanaClient, createPolicyReq)

	t.Log("Installing Elastic Defend")
	installElasticDefendPackage(t, info, policyResp.ID)

	t.Log("Polling for endpoint-security to become Healthy")
	ctx, cancel := context.WithTimeout(context.Background(), endpointHealthPollingTimeout)
	defer cancel()

	agentClient := fixture.Client()
	err = agentClient.Connect(ctx)
	require.NoError(t, err)

	require.Eventually(t,
		func() bool { return agentAndEndpointAreHealthy(t, ctx, agentClient) },
		endpointHealthPollingTimeout,
		time.Second,
		"Endpoint component or units are not healthy.",
	)
	t.Log("Verified endpoint component and units are healthy")

	// Unenroll the agent
	t.Log("Unenrolling the agent")

	hostname, err := os.Hostname()
	require.NoError(t, err)

	agentID, err := tools.GetAgentIDByHostname(info.KibanaClient, hostname)
	require.NoError(t, err)

	_, err = info.KibanaClient.UnEnrollAgent(context.TODO(), kibana.UnEnrollAgentRequest{ID: agentID})
	require.NoError(t, err)

	t.Log("Waiting for inputs to stop")
	require.Eventually(t,
		func() bool {
			state, err := agentClient.State(ctx)
			if err != nil {
				t.Logf("Error getting agent state: %s", err)
				return false
			}

			if state.State != client.Healthy {
				t.Logf("Agent is not Healthy\n%+v", state)
				return false
			}

			if len(state.Components) != 0 {
				t.Logf("Components have not been stopped and uninstalled!\n%+v", state)
				return false
			}

			if state.FleetState != client.Failed {
				t.Logf("Fleet state has not been marked as failed yet!\n%+v", state)
				return false
			}

			return true
		},
		endpointHealthPollingTimeout,
		time.Second,
		"All components not removed.",
	)
	t.Log("Verified endpoint component and units are removed")

	// Verify that the Endpoint directory was correctly removed.
	// Regression test for https://github.com/elastic/elastic-agent/issues/3077
	agentInstallPath := fixture.WorkDir()
	files, err := os.ReadDir(filepath.Clean(filepath.Join(agentInstallPath, "..")))
	require.NoError(t, err)

	t.Logf("Checking directories at install path %s", agentInstallPath)
	for _, f := range files {
		if !f.IsDir() {
			continue
		}

		t.Log("Found directory", f.Name())
		require.False(t, strings.Contains(f.Name(), "Endpoint"), "Endpoint directory was not removed")
	}
}

// Installs the Elastic Defend package to cause the agent to install the endpoint-security service.
func installElasticDefendPackage(t *testing.T, info *define.Info, policyID string) {
	t.Helper()

	t.Log("Templating endpoint package policy request")
	tmpl, err := template.New("pkgpolicy").Parse(endpointPackagePolicyTemplate)
	require.NoError(t, err)

	packagePolicyID := uuid.New().String()
	var pkgPolicyBuf bytes.Buffer
	err = tmpl.Execute(&pkgPolicyBuf, endpointPackageTemplateVars{
		ID:       packagePolicyID,
		Name:     "Defend-" + packagePolicyID,
		PolicyID: policyID,
		Version:  endpointPackageVersion,
	})
	require.NoError(t, err)

	// Make sure the templated value is actually valid JSON before making the API request.
	// Using json.Unmarshal will give us the actual syntax error, calling json.Valid() would not.
	packagePolicyReq := tools.PackagePolicyRequest{}
	err = json.Unmarshal(pkgPolicyBuf.Bytes(), &packagePolicyReq)
	require.NoErrorf(t, err, "Templated package policy is not valid JSON:\n%s", pkgPolicyBuf.String())

	t.Log("POST /api/fleet/package_policies")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	pkgResp, err := tools.InstallFleetPackage(ctx, info.KibanaClient, &packagePolicyReq)
	require.NoError(t, err)
	t.Logf("Endpoint package Policy Response:\n%+v", pkgResp)
}

func agentAndEndpointAreHealthy(t *testing.T, ctx context.Context, agentClient client.Client) bool {
	t.Helper()

	state, err := agentClient.State(ctx)
	if err != nil {
		t.Logf("Error getting agent state: %s", err)
		return false
	}

	if state.State != client.Healthy {
		t.Logf("Agent is not Healthy\n%+v", state)
		return false
	}

	foundEndpointInputUnit := false
	foundEndpointOutputUnit := false
	for _, comp := range state.Components {
		isEndpointComponent := strings.Contains(comp.Name, "endpoint")
		if comp.State != client.Healthy {
			t.Logf("Component is not Healthy\n%+v", comp)
			return false
		}

		for _, unit := range comp.Units {
			if isEndpointComponent {
				if unit.UnitType == client.UnitTypeInput {
					foundEndpointInputUnit = true
				}
				if unit.UnitType == client.UnitTypeOutput {
					foundEndpointOutputUnit = true
				}
			}

			if unit.State != client.Healthy {
				t.Logf("Unit is not Healthy\n%+v", unit)
				return false
			}
		}
	}

	// Ensure both the endpoint input and output units were found and healthy.
	if !foundEndpointInputUnit || !foundEndpointOutputUnit {
		t.Logf("State did not contain endpoint units!\n%+v", state)
		return false
	}

	return true
}
