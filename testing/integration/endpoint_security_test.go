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
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"text/template"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-libs/kibana"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/pkg/control/v2/client"
	"github.com/elastic/elastic-agent/pkg/control/v2/cproto"
	atesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/tools"
	"github.com/elastic/elastic-agent/pkg/testing/tools/fleet"
	"github.com/elastic/elastic-agent/pkg/testing/tools/testcontext"
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

var protectionTests = []struct {
	name      string
	protected bool
}{
	{
		name: "unprotected",
	},
	{
		name:      "protected",
		protected: true,
	},
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
		OS: []define.OS{
			{Type: define.Linux},
		},
	})

	for _, tc := range protectionTests {
		t.Run(tc.name, func(t *testing.T) {
			testInstallAndCLIUninstallWithEndpointSecurity(t, info, tc.protected)
		})
	}
}

// Tests that the agent can install and uninstall the endpoint-security service while remaining
// healthy. In this case endpoint-security is uninstalled because the agent was unenrolled, which
// triggers the creation of an empty agent policy removing all inputs (only when not force
// unenrolling). The empty agent policy triggers the uninstall of endpoint because endpoint was
// removed from the policy.
//
// Like the CLI uninstall test, the agent is uninstalled from the command line at the end of the test
// but at this point endpoint is already uninstalled.
func TestInstallAndUnenrollWithEndpointSecurity(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Stack:   &define.Stack{},
		Local:   false, // requires Agent installation
		Isolate: false,
		Sudo:    true, // requires Agent installation
		OS: []define.OS{
			{Type: define.Linux},
		},
	})

	for _, tc := range protectionTests {
		t.Run(tc.name, func(t *testing.T) {
			testInstallAndUnenrollWithEndpointSecurity(t, info, tc.protected)
		})
	}
}

// Tests that the agent can install and uninstall the endpoint-security service
// after the Elastic Defend integration was removed from the policy
// while remaining healthy.
//
// Installing endpoint-security requires a Fleet managed agent with the Elastic Defend integration
// installed. The endpoint-security service is uninstalled the Elastic Defend integration was removed from the policy.
//
// Like the CLI uninstall test, the agent is uninstalled from the command line at the end of the test
// but at this point endpoint should be already uninstalled.

func TestInstallWithEndpointSecurityAndRemoveEndpointIntegration(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Stack:   &define.Stack{},
		Local:   false, // requires Agent installation
		Isolate: false,
		Sudo:    true, // requires Agent installation
		OS: []define.OS{
			{Type: define.Linux},
		},
	})

	for _, tc := range protectionTests {
		t.Run(tc.name, func(t *testing.T) {
			testInstallWithEndpointSecurityAndRemoveEndpointIntegration(t, info, tc.protected)
		})
	}
}

// Tests that install of Elastic Defend fails if Agent is installed in a base
// path other than default
func TestEndpointSecurityNonDefaultBasePath(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Stack:   &define.Stack{},
		Local:   false, // requires Agent installation
		Isolate: false,
		Sudo:    true, // requires Agent installation
	})

	ctx, cn := context.WithCancel(context.Background())
	defer cn()

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
	installOpts := atesting.InstallOpts{
		NonInteractive: true,
		Force:          true,
		BasePath:       filepath.Join(paths.DefaultBasePath, "not_default"),
	}
	policyResp, err := tools.InstallAgentWithPolicy(t, ctx, installOpts, fixture, info.KibanaClient, createPolicyReq)
	require.NoErrorf(t, err, "Policy Response was: %v", policyResp)

	t.Log("Installing Elastic Defend")
	pkgPolicyResp, err := installElasticDefendPackage(t, info, policyResp.ID)
	require.NoErrorf(t, err, "Policy Response was: %v", pkgPolicyResp)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	c := fixture.Client()

	require.Eventually(t, func() bool {
		err := c.Connect(ctx)
		if err != nil {
			t.Logf("connecting client to agent: %v", err)
			return false
		}
		defer c.Disconnect()
		state, err := c.State(ctx)
		if err != nil {
			t.Logf("error getting the agent state: %v", err)
			return false
		}
		t.Logf("agent state: %+v", state)
		if state.State != cproto.State_DEGRADED {
			return false
		}
		for _, c := range state.Components {
			if strings.Contains(c.Message,
				"Elastic Defend requires Elastic Agent be installed at the default installation path") {
				return true
			}
		}
		return false
	}, 2*time.Minute, 10*time.Second, "Agent never became DEGRADED with default install message")
}

// buildPolicyWithTamperProtection helper function to build the policy request with or without tamper protection
func buildPolicyWithTamperProtection(policy kibana.AgentPolicy, protected bool) kibana.AgentPolicy {
	if protected {
		policy.AgentFeatures = append(policy.AgentFeatures, map[string]interface{}{
			"name":    "tamper_protection",
			"enabled": true,
		})
	}
	policy.IsProtected = protected
	return policy
}

func testInstallAndCLIUninstallWithEndpointSecurity(t *testing.T, info *define.Info, protected bool) {
	deadline := time.Now().Add(10 * time.Minute)
	ctx, cancel := testcontext.WithDeadline(t, context.Background(), deadline)
	defer cancel()

	// Get path to agent executable.
	fixture, err := define.NewFixture(t, define.Version())
	require.NoError(t, err, "could not create agent fixture")

	t.Log("Enrolling the agent in Fleet")
	policyUUID := uuid.New().String()

	createPolicyReq := buildPolicyWithTamperProtection(
		kibana.AgentPolicy{
			Name:        "test-policy-" + policyUUID,
			Namespace:   "default",
			Description: "Test policy " + policyUUID,
			MonitoringEnabled: []kibana.MonitoringEnabledOption{
				kibana.MonitoringEnabledLogs,
				kibana.MonitoringEnabledMetrics,
			},
		},
		protected,
	)

	installOpts := atesting.InstallOpts{
		NonInteractive: true,
		Force:          true,
	}

	policy, err := tools.InstallAgentWithPolicy(t, ctx,
		installOpts, fixture, info.KibanaClient, createPolicyReq)
	require.NoError(t, err, "failed to install agent with policy")

	t.Log("Installing Elastic Defend")
	pkgPolicyResp, err := installElasticDefendPackage(t, info, policy.ID)
	require.NoErrorf(t, err, "Policy Response was: %v", pkgPolicyResp)

	t.Log("Polling for endpoint-security to become Healthy")
	ctx, cancel = context.WithTimeout(ctx, endpointHealthPollingTimeout)
	defer cancel()

	agentClient := fixture.Client()
	err = agentClient.Connect(ctx)
	require.NoError(t, err, "could not connect to local agent")

	require.Eventually(t,
		func() bool { return agentAndEndpointAreHealthy(t, ctx, agentClient) },
		endpointHealthPollingTimeout,
		time.Second,
		"Endpoint component or units are not healthy.",
	)
	t.Log("Verified endpoint component and units are healthy")
}

func testInstallAndUnenrollWithEndpointSecurity(t *testing.T, info *define.Info, protected bool) {
	// Get path to agent executable.
	fixture, err := define.NewFixture(t, define.Version())
	require.NoError(t, err)

	t.Log("Enrolling the agent in Fleet")
	policyUUID := uuid.New().String()
	createPolicyReq := buildPolicyWithTamperProtection(
		kibana.AgentPolicy{
			Name:        "test-policy-" + policyUUID,
			Namespace:   "default",
			Description: "Test policy " + policyUUID,
			MonitoringEnabled: []kibana.MonitoringEnabledOption{
				kibana.MonitoringEnabledLogs,
				kibana.MonitoringEnabledMetrics,
			},
		},
		protected,
	)

	installOpts := atesting.InstallOpts{
		NonInteractive: true,
		Force:          true,
	}

	ctx, cn := context.WithCancel(context.Background())
	defer cn()

	policy, err := tools.InstallAgentWithPolicy(t, ctx, installOpts, fixture, info.KibanaClient, createPolicyReq)
	require.NoError(t, err)

	t.Log("Installing Elastic Defend")
	installElasticDefendPackage(t, info, policy.ID)

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

	agentID, err := fleet.AgentIDByHostname(info.KibanaClient, hostname)
	require.NoError(t, err)

	_, err = info.KibanaClient.UnEnrollAgent(ctx, kibana.UnEnrollAgentRequest{ID: agentID})
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

func testInstallWithEndpointSecurityAndRemoveEndpointIntegration(t *testing.T, info *define.Info, protected bool) {
	// Get path to agent executable.
	fixture, err := define.NewFixture(t, define.Version())
	require.NoError(t, err)

	t.Log("Enrolling the agent in Fleet")
	policyUUID := uuid.New().String()
	createPolicyReq := buildPolicyWithTamperProtection(
		kibana.AgentPolicy{
			Name:        "test-policy-" + policyUUID,
			Namespace:   "default",
			Description: "Test policy " + policyUUID,
			MonitoringEnabled: []kibana.MonitoringEnabledOption{
				kibana.MonitoringEnabledLogs,
				kibana.MonitoringEnabledMetrics,
			},
		},
		protected,
	)

	installOpts := atesting.InstallOpts{
		NonInteractive: true,
		Force:          true,
	}

	ctx, cn := context.WithCancel(context.Background())
	defer cn()

	policy, err := tools.InstallAgentWithPolicy(t, ctx, installOpts, fixture, info.KibanaClient, createPolicyReq)
	require.NoError(t, err)

	t.Log("Installing Elastic Defend")
	pkgPolicyResp, err := installElasticDefendPackage(t, info, policy.ID)
	require.NoErrorf(t, err, "Policy Response was: %#v", pkgPolicyResp)

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

	t.Logf("Removing Elastic Defend: %v", fmt.Sprintf("/api/fleet/package_policies/%v", pkgPolicyResp.Item.ID))
	_, err = info.KibanaClient.DeleteFleetPackage(ctx, pkgPolicyResp.Item.ID)
	require.NoError(t, err)

	t.Log("Waiting for endpoint to stop")
	require.Eventually(t,
		func() bool { return agentIsHealthyNoEndpoint(t, ctx, agentClient) },
		endpointHealthPollingTimeout,
		time.Second,
		"Endpoint component or units are still present.",
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

// This is a subset of kibana.AgentPolicyUpdateRequest, using until elastic-agent-libs PR https://github.com/elastic/elastic-agent-libs/pull/141 is merged
// TODO: replace with the elastic-agent-libs when available
type agentPolicyUpdateRequest struct {
	// Name of the policy. Required in an update request.
	Name string `json:"name"`
	// Namespace of the policy. Required in an update request.
	Namespace   string `json:"namespace"`
	IsProtected bool   `json:"is_protected"`
}

// Installs the Elastic Defend package to cause the agent to install the endpoint-security service.
func installElasticDefendPackage(t *testing.T, info *define.Info, policyID string) (r kibana.PackagePolicyResponse, err error) {
	t.Helper()

	t.Log("Templating endpoint package policy request")
	tmpl, err := template.New("pkgpolicy").Parse(endpointPackagePolicyTemplate)
	if err != nil {
		return r, fmt.Errorf("error creating new template: %w", err)
	}

	packagePolicyID := uuid.New().String()
	var pkgPolicyBuf bytes.Buffer

	// Need unique name for Endpoint integration otherwise on multiple runs on the same instance you get
	// http error response with code 409: {StatusCode:409 Error:Conflict Message:An integration policy with the name Defend-cbomziz4uvn5fov9t1gsrcvdwn2p1s7tefnvgsye already exists. Please rename it or choose a different name.}
	err = tmpl.Execute(&pkgPolicyBuf, endpointPackageTemplateVars{
		ID:       packagePolicyID,
		Name:     "Defend-" + packagePolicyID,
		PolicyID: policyID,
		Version:  endpointPackageVersion,
	})
	if err != nil {
		return r, fmt.Errorf("error executing template: %w", err)
	}

	// Make sure the templated value is actually valid JSON before making the API request.
	// Using json.Unmarshal will give us the actual syntax error, calling json.Valid() would not.
	packagePolicyReq := kibana.PackagePolicyRequest{}
	err = json.Unmarshal(pkgPolicyBuf.Bytes(), &packagePolicyReq)
	if err != nil {
		return r, fmt.Errorf("templated package policy is not valid JSON: %s, %w", pkgPolicyBuf.String(), err)
	}

	t.Log("POST /api/fleet/package_policies")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	pkgResp, err := info.KibanaClient.InstallFleetPackage(ctx, packagePolicyReq)
	if err != nil {
		t.Logf("Error installing fleet package: %v", err)
		return r, fmt.Errorf("error installing fleet package: %w", err)
	}
	t.Logf("Endpoint package Policy Response:\n%+v", pkgResp)
	return pkgResp, err
}

func agentAndEndpointAreHealthy(t *testing.T, ctx context.Context, agentClient client.Client) bool {
	t.Helper()

	state, err := agentClient.State(ctx)
	if err != nil {
		t.Logf("Error getting agent state: %s", err)
		return false
	}

	if state.State != client.Healthy {
		t.Logf("local Agent is not Healthy: current state: %+v", state)
		return false
	}

	foundEndpointInputUnit := false
	foundEndpointOutputUnit := false
	for _, comp := range state.Components {
		isEndpointComponent := strings.Contains(comp.Name, "endpoint")
		if comp.State != client.Healthy {
			t.Logf("endpoint component is not Healthy: current state: %+v", comp)
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
				t.Logf("unit %q is not Healthy\n%+v", unit.UnitID, unit)
				return false
			}
		}
	}

	// Ensure both the endpoint input and output units were found and healthy.
	if !foundEndpointInputUnit || !foundEndpointOutputUnit {
		t.Logf("State did not contain endpoint units. state: %+v", state)
		return false
	}

	return true
}

func agentIsHealthyNoEndpoint(t *testing.T, ctx context.Context, agentClient client.Client) bool {
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

	foundEndpointComponent := false
	foundEndpointInputUnit := false
	foundEndpointOutputUnit := false
	for _, comp := range state.Components {
		isEndpointComponent := strings.Contains(comp.Name, "endpoint")
		if isEndpointComponent {
			foundEndpointComponent = true
		}
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
	if foundEndpointComponent || foundEndpointInputUnit || foundEndpointOutputUnit {
		t.Logf("State did contain endpoint or endpoint units!\n%+v", state)
		return false
	}

	return true
}
