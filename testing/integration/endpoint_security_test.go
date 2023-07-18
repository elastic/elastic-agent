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
// fxiture.Install via tools.InstallAgentWithPolicy. Failure to uninstall the agent will fail the
// test automatically.
func TestEndpointSecurity(t *testing.T) {
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

	healthyEndpointFunc := func() bool {
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
	require.Eventually(t, healthyEndpointFunc, endpointHealthPollingTimeout, time.Second, "Endpoint component or units are not healthy.")
	t.Logf("Verified endpoint component and units are healthy")
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
		Name:     "Defend-" + info.Namespace,
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
