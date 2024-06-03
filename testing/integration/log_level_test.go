// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build integration

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"
	"text/template"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v2"

	"github.com/elastic/elastic-agent-libs/kibana"
	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/elastic-agent/pkg/control/v2/client"
	"github.com/elastic/elastic-agent/pkg/core/logger"
	atesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/tools/fleettools"
	"github.com/elastic/elastic-agent/pkg/testing/tools/testcontext"
	"github.com/elastic/elastic-agent/pkg/utils"
)

func TestSetLogLevelFleetManaged(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Group: Default,
		Stack: &define.Stack{},
	})

	deadline := time.Now().Add(10 * time.Minute)
	ctx, cancel := testcontext.WithDeadline(t, context.Background(), deadline)
	defer cancel()

	f, err := define.NewFixtureFromLocalBuild(t, define.Version())
	require.NoError(t, err, "failed creating agent fixture")

	testSetLogLevel := createTestSetLogLevelFunction(ctx, t, f, info)

	f.Run(ctx, atesting.State{
		AgentState: atesting.NewClientState(client.Healthy),
		After:      testSetLogLevel,
	})

}

func createTestSetLogLevelFunction(ctx context.Context, t *testing.T, f *atesting.Fixture, info *define.Info) func(ctx context.Context) error {
	policyResp, enrollmentTokenResp := createPolicyAndEnrollmentToken(ctx, t, info.KibanaClient, createBasicPolicy())

	t.Logf("Created policy %+v", policyResp.AgentPolicy)

	t.Log("Getting default Fleet Server URL...")
	fleetServerURL, err := fleettools.DefaultURL(ctx, info.KibanaClient)
	require.NoError(t, err, "failed getting Fleet Server URL")

	t.Cleanup(func() {
		timeoutCtx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		err := info.KibanaClient.DeletePolicy(timeoutCtx, policyResp.ID)
		assert.NoError(t, err, "error deleting policy %s", policyResp.ID)
	})

	// the actual test function is the one below
	return testLogLevelSetViaFleet(f, fleetServerURL, enrollmentTokenResp, t, info, policyResp)
}

func testLogLevelSetViaFleet(f *atesting.Fixture, fleetServerURL string, enrollmentTokenResp kibana.CreateEnrollmentAPIKeyResponse, t *testing.T, info *define.Info, policyResp kibana.PolicyResponse) func(ctx context.Context) error {
	return func(ctx context.Context) error {

		out, err := f.Exec(ctx, []string{"enroll", "--url", fleetServerURL, "--enrollment-token", enrollmentTokenResp.APIKey})
		require.NoErrorf(t, err, "error enrolling agent. Enroll command output:\n%s\n", string(out))

		state, err := f.Client().State(ctx)
		require.NoError(t, err, "error getting state for agent")

		t.Cleanup(unenrollAgentFunction(ctx, t, info.KibanaClient, state.Info.ID))

		// Step 0: get the initial log level reported by agent
		initialLogLevel, err := getLogLevelForAgent(ctx, t, f)
		require.NoError(t, err, "error retrieving agent log level")
		assert.Equal(t, logger.DefaultLogLevel, initialLogLevel, "unexpected default log level at agent startup")

		// Step 1: set a different log level in Fleet policy
		policyLogLevel := logp.ErrorLevel

		// make sure we are changing something
		require.NotEqualf(t, logger.DefaultLogLevel, policyLogLevel, "Policy log level %s should be different than agent default log level", policyLogLevel)

		// set policy log level and verify that eventually the agent sets it
		err = updatePolicyLogLevel(ctx, info.KibanaClient, policyResp.AgentPolicy, policyLogLevel.String())
		require.NoError(t, err, "error updating policy log level")

		// get the agent ID
		agentID, err := getAgentID(ctx, t, f)
		require.NoError(t, err, "error getting the agent ID")

		// assert `elastic-agent inspect` eventually reports the new log level
		assert.Eventuallyf(t, func() bool {
			agentLogLevel, err := getLogLevelForAgent(ctx, t, f)
			if err != nil {
				t.Logf("error getting log level from agent: %v", err)
				return false
			}
			t.Logf("Agent log level: %q policy log level: %q", agentLogLevel, policyLogLevel)
			return agentLogLevel == policyLogLevel.String()
		}, 2*time.Minute, time.Second, "agent never received expected log level %q", policyLogLevel)

		// assert Fleet eventually receives the new log level from agent through checkin
		assert.Eventuallyf(t, func() bool {
			fleetMetadataLogLevel, err := getLogLevelFromFleetMetadata(ctx, info.KibanaClient, agentID)
			if err != nil {
				t.Logf("error getting log level for agent %q from Fleet metadata: %v", agentID, err)
				return false
			}
			t.Logf("Fleet metadata log level for agent %q: %q policy log level: %q", agentID, fleetMetadataLogLevel, policyLogLevel)
			return fleetMetadataLogLevel == policyLogLevel.String()
		}, 2*time.Minute, time.Second, "agent never communicated policy log level %q to Fleet", policyLogLevel)

		// Step 2: set a different log level for the specific agent using Settings action
		// set agent log level and verify that it takes precedence over the policy one
		agentLogLevel := logp.DebugLevel.String()
		err = updateAgentLogLevel(ctx, info.KibanaClient, agentID, agentLogLevel)
		require.NoError(t, err, "error updating agent log level")

		assert.Eventuallyf(t, func() bool {
			actualAgentLogLevel, err := getLogLevelForAgent(ctx, t, f)
			if err != nil {
				t.Logf("error getting log level from agent: %v", err)
				return false
			}
			t.Logf("Agent log level: %q, expected level: %q", actualAgentLogLevel, agentLogLevel)
			return actualAgentLogLevel == agentLogLevel
		}, 2*time.Minute, time.Second, "agent never received agent-specific log level %q", agentLogLevel)

		// assert Fleet eventually receives the new log level from agent through checkin
		assert.Eventuallyf(t, func() bool {
			fleetMetadataLogLevel, err := getLogLevelFromFleetMetadata(ctx, info.KibanaClient, agentID)
			if err != nil {
				t.Logf("error getting log level for agent %q from Fleet metadata: %v", agentID, err)
				return false
			}
			t.Logf("Fleet metadata log level for agent %q: %q agent log level: %q", agentID, fleetMetadataLogLevel, policyLogLevel)
			return fleetMetadataLogLevel == agentLogLevel
		}, 2*time.Minute, time.Second, "agent never communicated agent-specific log level %q to Fleet", policyLogLevel)

		// Step 3: Clear the agent-specific log level override, verify that we revert to policy log level
		err = updateAgentLogLevel(ctx, info.KibanaClient, agentID, "")
		require.NoError(t, err, "error clearing agent log level")

		// assert `elastic-agent inspect` eventually reports the new log level
		assert.Eventuallyf(t, func() bool {
			actualAgentLogLevel, err := getLogLevelForAgent(ctx, t, f)
			if err != nil {
				t.Logf("error getting log level from agent: %v", err)
				return false
			}
			t.Logf("Agent log level: %q policy log level: %q", actualAgentLogLevel, policyLogLevel)
			return actualAgentLogLevel == policyLogLevel.String()
		}, 2*time.Minute, time.Second, "agent never reverted to policy log level %q", policyLogLevel)

		// assert Fleet eventually receives the new log level from agent through checkin
		assert.Eventuallyf(t, func() bool {
			fleetMetadataLogLevel, err := getLogLevelFromFleetMetadata(ctx, info.KibanaClient, agentID)
			if err != nil {
				t.Logf("error getting log level for agent %q from Fleet metadata: %v", agentID, err)
				return false
			}
			t.Logf("Fleet metadata log level for agent %q: %q policy log level: %q", agentID, fleetMetadataLogLevel, policyLogLevel)
			return fleetMetadataLogLevel == policyLogLevel.String()
		}, 2*time.Minute, time.Second, "agent never communicated reverting to policy log level %q to Fleet", policyLogLevel)

		// Step 4: Clear the log level in policy and verify that agent reverts to the initial log level
		err = updatePolicyLogLevel(ctx, info.KibanaClient, policyResp.AgentPolicy, "")
		require.NoError(t, err, "error clearing policy log level")

		// assert `elastic-agent inspect` eventually reports the initial log level
		assert.Eventuallyf(t, func() bool {
			actualAgentLogLevel, err := getLogLevelForAgent(ctx, t, f)
			if err != nil {
				t.Logf("error getting log level from agent: %v", err)
				return false
			}
			t.Logf("Agent log level: %q initial log level: %q", actualAgentLogLevel, initialLogLevel)
			return actualAgentLogLevel == policyLogLevel.String()
		}, 2*time.Minute, time.Second, "agent never reverted to initial log level %q", policyLogLevel)

		// assert Fleet eventually receives the new log level from agent through checkin
		assert.Eventuallyf(t, func() bool {
			fleetMetadataLogLevel, err := getLogLevelFromFleetMetadata(ctx, info.KibanaClient, agentID)
			if err != nil {
				t.Logf("error getting log level for agent %q from Fleet metadata: %v", agentID, err)
				return false
			}
			t.Logf("Fleet metadata log level for agent %q: %q initial log level: %q", agentID, fleetMetadataLogLevel, policyLogLevel)
			return fleetMetadataLogLevel == policyLogLevel.String()
		}, 2*time.Minute, time.Second, "agent never communicated initial log level %q to Fleet", policyLogLevel)

		return nil
	}
}

func updateAgentLogLevel(ctx context.Context, kibanaClient *kibana.Client, agentID string, logLevel string) error {
	updateLogLevelTemplateString := `{
		"action": {
			"type": "SETTINGS",
				"data": {
				"log_level": "{{ .logLevel }}"
			}
		}
	}`
	updateLogLevelTemplate, err := template.New("updatePolicyLogLevel").Parse(updateLogLevelTemplateString)
	if err != nil {
		return fmt.Errorf("error parsing update log level request template: %w", err)
	}

	buf := new(bytes.Buffer)
	err = updateLogLevelTemplate.Execute(buf, map[string]string{"logLevel": logLevel})

	_, err = kibanaClient.SendWithContext(ctx, http.MethodPost, "/api/fleet/agents/"+agentID+"/actions", nil, nil, buf)
	if err != nil {
		return fmt.Errorf("error executing fleet request: %w", err)
	}

	return nil
}

func updatePolicyLogLevel(ctx context.Context, kibanaClient *kibana.Client, policy kibana.AgentPolicy, newPolicyLogLevel string) error {
	// The request we would need is the one below, but at the time of writing there is no way to set overrides with fleet api definition in elastic-agent-libs, need to update
	// info.KibanaClient.UpdatePolicy(ctx, policyResp.ID, kibana.AgentPolicyUpdateRequest{})
	// Let's do a generic HTTP request

	updateLogLevelTemplateString := `{
	   "name": "{{ .policyName }}",
	   "namespace": "{{ .namespace }}",
	   "overrides": {
		   "agent":{
			 "logging": {
			   "level": "{{ .logLevel }}"
			 }
		   }
	   }
	}`
	updateLogLevelTemplate, err := template.New("updatePolicyLogLevel").Parse(updateLogLevelTemplateString)
	if err != nil {
		return fmt.Errorf("error parsing update log level request template: %w", err)
	}

	buf := new(bytes.Buffer)
	err = updateLogLevelTemplate.Execute(buf, map[string]string{"policyName": policy.Name, "namespace": policy.Namespace, "logLevel": newPolicyLogLevel})
	if err != nil {
		return fmt.Errorf("error rendering policy update template: %w", err)
	}

	_, err = kibanaClient.SendWithContext(ctx, http.MethodPut, "/api/fleet/agent_policies/"+policy.ID, nil, nil, buf)

	if err != nil {
		return fmt.Errorf("error executing fleet request: %w", err)
	}

	return nil
}

func getAgentID(ctx context.Context, t *testing.T, f *atesting.Fixture) (string, error) {
	inspectOutput, err := agentInspect(ctx, t, f)
	if err != nil {
		return "", fmt.Errorf("inspecting agent config: %w", err)
	}
	t.Logf("inspect output:\n%s\n", inspectOutput)
	rawAgentId, err := utils.GetNestedMap(inspectOutput, "agent", "id")
	if err != nil {
		return "", fmt.Errorf("error looking up agent id in inspect output: %w", err)
	}
	if agentID, ok := rawAgentId.(string); ok {
		return agentID, nil
	}

	return "", fmt.Errorf("agent id is not a string: %T", rawAgentId)
}

func getLogLevelForAgent(ctx context.Context, t *testing.T, f *atesting.Fixture) (string, error) {
	inspectOutput, err := agentInspect(ctx, t, f)
	if err != nil {
		return "", fmt.Errorf("error retrieving log level: %w", err)
	}

	actualLogLevel, err := utils.GetNestedMap[string](inspectOutput, "agent", "logging", "level")
	if err != nil {
		return "", fmt.Errorf("error retrieving log level from inspect output: %w", err)
	}

	if logLevelString, ok := actualLogLevel.(string); ok {
		return logLevelString, nil
	}

	return "", fmt.Errorf("loglevel from inspect output is not a string: %T", actualLogLevel)
}

func getLogLevelFromFleetMetadata(ctx context.Context, kibanaClient *kibana.Client, agentID string) (string, error) {
	// The request we would need is kibanaClient.GetAgent(), but at the time of writing there is no way to get loglevel with fleet api definition in elastic-agent-libs, need to update
	// kibana.AgentCommon struct to pick up log level from `local_metadata`
	// Let's do a generic HTTP request

	response, err := kibanaClient.SendWithContext(ctx, http.MethodGet, "/api/fleet/agents/"+agentID, nil, nil, nil)
	if err != nil {
		return "", fmt.Errorf("getting agent from Fleet: %w", err)
	}
	defer response.Body.Close()

	responseBodyBytes, err := io.ReadAll(response.Body)
	if err != nil {
		return "", fmt.Errorf("reading response body from Fleet: %w", err)
	}

	rawJson := map[string]any{}
	err = json.Unmarshal(responseBodyBytes, &rawJson)
	if err != nil {
		return "", fmt.Errorf("unmarshalling Fleet response: %w", err)
	}
	rawLogLevel, err := utils.GetNestedMap(rawJson, "item", "local_metadata", "elastic", "agent", "log_level")
	if err != nil {
		return "", fmt.Errorf("looking for item/local_metadata/elastic/agent/log_level key in Fleet response: %w", err)
	}

	if logLevel, ok := rawLogLevel.(string); ok {
		return logLevel, nil
	}
	return "", fmt.Errorf("loglevel from Fleet output is not a string: %T", rawLogLevel)
}

func agentInspect(ctx context.Context, t *testing.T, f *atesting.Fixture) (map[string]any, error) {
	inspectOutBytes, err := f.Exec(ctx, []string{"inspect"})
	t.Logf("inspect output:\n%s\n", string(inspectOutBytes))
	if err != nil {
		return nil, fmt.Errorf("unable to run elastic-agent inspect: %w", err)
	}
	inspectOutput := map[string]any{}
	err = yaml.Unmarshal(inspectOutBytes, &inspectOutput)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling inspect output: %w", err)
	}
	return inspectOutput, nil
}

func unenrollAgentFunction(ctx context.Context, t *testing.T, client *kibana.Client, id string) func() {
	return func() {
		_, err := client.UnEnrollAgent(ctx, kibana.UnEnrollAgentRequest{
			ID:     id,
			Revoke: false,
		})
		assert.NoError(t, err, "error unenrolling agent")
	}
}

func createPolicyAndEnrollmentToken(ctx context.Context, t *testing.T, kibClient *kibana.Client, policy kibana.AgentPolicy) (kibana.PolicyResponse, kibana.CreateEnrollmentAPIKeyResponse) {
	t.Log("Creating Agent policy...")
	policyResp, err := kibClient.CreatePolicy(ctx, policy)
	require.NoError(t, err, "failed creating policy")

	t.Log("Creating Agent enrollment API key...")
	createEnrollmentApiKeyReq := kibana.CreateEnrollmentAPIKeyRequest{
		PolicyID: policyResp.ID,
	}
	enrollmentToken, err := kibClient.CreateEnrollmentAPIKey(ctx, createEnrollmentApiKeyReq)
	require.NoError(t, err, "failed creating enrollment API key")
	return policyResp, enrollmentToken
}
func createBasicPolicy() kibana.AgentPolicy {
	policyUUID := uuid.New().String()
	return kibana.AgentPolicy{
		Name:              "testloglevel-policy-" + policyUUID,
		Namespace:         "default",
		Description:       "Test Log Level Policy " + policyUUID,
		MonitoringEnabled: []kibana.MonitoringEnabledOption{},
	}
}
