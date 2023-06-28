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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/google/uuid"

	"github.com/elastic/elastic-agent-libs/kibana"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/tools"
)

//go:embed endpoint_security_package_policy.json
var endpointPackagePolicyJSON []byte

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
		Sudo:    true,                                                  // requires Agent installation
		OS:      []define.OS{{Type: define.Linux, Arch: define.AMD64}}, // only run on Linux AMD64 during development.
	})

	// Get path to Elastic Agent executable
	fixture, err := define.NewFixture(t)
	require.NoError(t, err)

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
	require.Eventually(t, tools.WaitForAgentStatus(t, info.KibanaClient, "online"), 2*time.Minute, 10*time.Second, "Agent status is not online")

	t.Log("Creating endpoint package policy request")
	packagePolicyReq := PackagePolicyRequest{}
	err = json.Unmarshal(endpointPackagePolicyJSON, &packagePolicyReq)
	require.NoError(t, err)

	// TODO: Set the Package.Version to the last minor release.
	packagePolicyReq.PolicyID = policy.ID
	jsonPackagePolicyReq, err := json.Marshal(packagePolicyReq)
	require.NoError(t, err)

	t.Log("POSTing endpoint package policy request")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	resp, err := info.KibanaClient.Connection.SendWithContext(ctx,
		http.MethodPost,
		"/api/fleet/package_policies",
		nil,
		nil,
		bytes.NewReader(jsonPackagePolicyReq),
	)
	require.NoError(t, err)
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	if !assert.Equal(t, http.StatusOK, resp.StatusCode) {
		fleetErrorResp := FleetErrorResponse{}
		err = json.Unmarshal(bodyBytes, &fleetErrorResp)
		require.NoError(t, err)
		t.Logf("Fleet Error Response:\n%+v", fleetErrorResp)
		t.FailNow()
	}

	t.Log(string(bodyBytes))
	packagePolicyResp := PackagePolicyResponse{}
	err = json.Unmarshal(bodyBytes, &packagePolicyResp)
	require.NoError(t, err)
	t.Logf("Package Policy Response:\n%+v", packagePolicyResp)

	t.Log("GETing updated agent policy")
	policyResp, err := info.KibanaClient.GetPolicy(policy.ID)
	t.Logf("Agent Policy with Endpoint:\n%+v", policyResp)

	// TODO: Get new agent policy and parse out endpoint component IDs
	// TODO: Make sure endpoint is healthy.
	// ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	// defer cancel()

	// err = fixture.Run(ctx, atesting.State{
	// 	Configure:  simpleConfig1,
	// 	AgentState: atesting.NewClientState(client.Healthy),
	// 	Components: map[string]atesting.ComponentState{
	// 		"endpoint-default": {
	// 			State: atesting.NewClientState(client.Healthy),
	// 			Units: map[atesting.ComponentUnitKey]atesting.ComponentUnitState{
	// 				atesting.ComponentUnitKey{UnitType: client.UnitTypeOutput, UnitID: "endpoint-default"}: {
	// 					State: atesting.NewClientState(client.Healthy),
	// 				},
	// 				atesting.ComponentUnitKey{UnitType: client.UnitTypeInput, UnitID: "endpoint-default-TBD"}: {
	// 					State: atesting.NewClientState(client.Configuring),
	// 				},
	// 			},
	// 		},
	// 	},
	// })
	// require.NoError(t, err)
}
