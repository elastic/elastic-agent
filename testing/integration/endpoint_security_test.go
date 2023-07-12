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
	"io"
	"net/http"
	"strings"
	"testing"
	"text/template"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/google/uuid"

	"github.com/elastic/elastic-agent-libs/kibana"
	"github.com/elastic/elastic-agent/pkg/control/v2/client"
	atesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/tools"
)

// https://www.elastic.co/guide/en/fleet/8.8/fleet-apis.html#createPackagePolicy
// request https://www.elastic.co/guide/en/fleet/8.8/fleet-apis.html#package_policy_request
type PackagePolicyRequest struct {
	ID        string                      `json:"id,omitempty"`
	Name      string                      `json:"name"`
	Namespace string                      `json:"namespace"`
	PolicyID  string                      `json:"policy_id"`
	Package   PackagePolicyRequestPackage `json:"package"`
	Vars      map[string]interface{}      `json:"vars"`
	Inputs    []map[string]interface{}    `json:"inputs"`
	Force     bool                        `json:"force"`
}

type PackagePolicyRequestPackage struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// https://www.elastic.co/guide/en/fleet/8.8/fleet-apis.html#create_package_policy_200_response
type PackagePolicyResponse struct {
	Item PackagePolicy `json:"item"`
}

// https://www.elastic.co/guide/en/fleet/8.8/fleet-apis.html#package_policy
type PackagePolicy struct {
	ID          string                      `json:"id,omitempty"`
	Revision    int                         `json:"revision"`
	Enabled     bool                        `json:"enabled"`
	Inputs      []map[string]interface{}    `json:"inputs"`
	Package     PackagePolicyRequestPackage `json:"package"`
	Namespace   string                      `json:"namespace"`
	OutputID    string                      `json:"output_id"`
	PolicyID    string                      `json:"policy_id"`
	Name        string                      `json:"name"`
	Description string                      `json:"description"`
}

// https://www.elastic.co/guide/en/fleet/8.8/fleet-apis.html#fleet_server_health_check_400_response
type FleetErrorResponse struct {
	StatusCode int    `json:"statusCode"`
	Error      string `json:"error"`
	Message    string `json:"message"`
}

func TestEndpointSecurity(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Stack:   &define.Stack{},
		Local:   false, // requires Agent installation
		Isolate: false,
		Sudo:    true, // requires Agent installation
		// OS:      []define.OS{{Type: define.Linux, Arch: define.AMD64}}, // only run on Linux AMD64 during development.
	})

	// Get path to Elastic Agent executable
	fixture, err := define.NewFixture(t, define.Version())
	require.NoError(t, err)

	policyID := enrollAgentInFleet(t, info, fixture)
	installElasticDefendPackage(t, info, policyID)

	t.Log("Polling for endpoint-security to become Healthy")
	statePollingTimeout := 10 * time.Minute
	ctx, cancel := context.WithTimeout(context.Background(), statePollingTimeout)
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
		if !assert.True(t, foundEndpointInputUnit) || !assert.True(t, foundEndpointOutputUnit) {
			t.Logf("State did not contain endpoint units!\n%+v", state)
			return false
		}

		return true
	}
	require.Eventually(t, healthyEndpointFunc, statePollingTimeout, time.Second, "Endpoint component or units are not healthy.")
	t.Logf("Verified endpoint component and units are healthy")
}

// Installs the agent, enrolls it in Fleet, and returns the created policy ID.
func enrollAgentInFleet(t *testing.T, info *define.Info, fixture *atesting.Fixture) string {
	t.Log("Creating Agent policy...")
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
	policy, err := info.KibanaClient.CreatePolicy(createPolicyReq)
	require.NoError(t, err)

	t.Log("Creating Agent enrollment API key...")
	createEnrollmentApiKeyReq := kibana.CreateEnrollmentAPIKeyRequest{
		PolicyID: policy.ID,
	}
	enrollmentToken, err := info.KibanaClient.CreateEnrollmentAPIKey(createEnrollmentApiKeyReq)
	require.NoError(t, err)

	t.Log("Getting default Fleet Server URL...")
	fleetServerURL, err := tools.GetDefaultFleetServerURL(info.KibanaClient)
	require.NoError(t, err)

	t.Log("Enrolling Elastic Agent...")
	output, err := tools.InstallAgent(fleetServerURL, enrollmentToken.APIKey, fixture)
	if err != nil {
		t.Log(string(output))
	}
	require.NoError(t, err)

	t.Log(`Waiting for enrolled Agent status to be "online"...`)
	require.Eventually(t,
		tools.WaitForAgentStatus(t, info.KibanaClient, "online"),
		2*time.Minute,
		10*time.Second,
		"Agent status is not online",
	)

	return policy.ID
}

type endpointPackageTemplateVars struct {
	ID       string
	Name     string
	PolicyID string
	Version  string
}

//go:embed endpoint_security_package.json.tmpl
var endpointPackagePolicyTemplate string

// TODO: Setup a GitHub Action to update this for each release of https://github.com/elastic/endpoint-package
const endpointPackageVersion = "8.9.0"

// Installs the Elastic Defend package to cause the agent to install the endpoint-security service.
func installElasticDefendPackage(t *testing.T, info *define.Info, policyID string) {
	t.Helper()

	t.Log("Creating endpoint package policy request")
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
	packagePolicyReq := PackagePolicyRequest{}
	err = json.Unmarshal(pkgPolicyBuf.Bytes(), &packagePolicyReq)
	require.NoErrorf(t, err, "Templated package policy is not valid JSON:\n%s", pkgPolicyBuf.String())

	t.Log("POST /api/fleet/package_policies")
	pkgCtx, pkgCancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer pkgCancel()

	pkgResp, err := info.KibanaClient.Connection.SendWithContext(pkgCtx,
		http.MethodPost,
		"/api/fleet/package_policies",
		nil,
		nil,
		bytes.NewReader(pkgPolicyBuf.Bytes()),
	)
	require.NoError(t, err)
	defer pkgResp.Body.Close()

	pkgRespBytes, err := io.ReadAll(pkgResp.Body)
	require.NoError(t, err)

	if !assert.Equal(t, http.StatusOK, pkgResp.StatusCode) {
		fleetErrorResp := FleetErrorResponse{}
		err = json.Unmarshal(pkgRespBytes, &fleetErrorResp)
		require.NoError(t, err)
		t.Logf("Fleet Error Response:\n%+v", fleetErrorResp)
		t.FailNow()
	}

	packagePolicyResp := PackagePolicyResponse{}
	err = json.Unmarshal(pkgRespBytes, &packagePolicyResp)
	require.NoError(t, err)
	t.Logf("Endpoint package Policy Response:\n%+v", packagePolicyResp)
}
