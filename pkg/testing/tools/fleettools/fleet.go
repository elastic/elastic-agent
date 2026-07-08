// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package fleettools

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/gofrs/uuid/v5"

	"github.com/elastic/elastic-agent-libs/kibana"
)

type EnrollParams struct {
	EnrollmentToken string `json:"api_key"`
	FleetURL        string `json:"fleet_url"`
	PolicyID        string `json:"policy_id"`
}

func GetAgentStatus(ctx context.Context, client *kibana.Client, agentID string) (string, error) {
	agent, err := client.GetAgent(ctx, kibana.GetAgentRequest{ID: agentID})
	if err != nil {
		return "", err
	}
	return agent.Status, nil
}

func GetAgentVersion(ctx context.Context, client *kibana.Client, agentID string) (string, error) {
	agent, err := client.GetAgent(ctx, kibana.GetAgentRequest{ID: agentID})
	if err != nil {
		return "", err
	}
	return agent.Agent.Version, nil
}

func UnEnrollAgent(ctx context.Context, client *kibana.Client, agentID string) error {
	unEnrollAgentReq := kibana.UnEnrollAgentRequest{
		ID:     agentID,
		Revoke: true,
	}
	_, err := client.UnEnrollAgent(ctx, unEnrollAgentReq)
	if err != nil {
		return fmt.Errorf("unable to unenroll agent with ID [%s]: %w", agentID, err)
	}
	return nil
}

func UpgradeAgent(ctx context.Context, client *kibana.Client, agentID, version string, force bool) error {
	upgradeAgentReq := kibana.UpgradeAgentRequest{
		ID:      agentID,
		Version: version,
		Force:   force,
	}
	_, err := client.UpgradeAgent(ctx, upgradeAgentReq)
	if err != nil {
		return fmt.Errorf("unable to upgrade agent with ID [%s]: %w", agentID, err)
	}
	return nil
}

// RollbackAgent requests a rollback for the given agent via the Fleet API.
// TODO: Replace with a dedicated method once elastic-agent-libs supports
// the rollback endpoint (https://github.com/elastic/elastic-agent-libs/pull/399).
func RollbackAgent(ctx context.Context, client *kibana.Client, agentID string) error {
	apiURL := fmt.Sprintf("/api/fleet/agents/%s/rollback", agentID)
	resp, err := client.SendWithContext(ctx, http.MethodPost, apiURL, nil, nil, nil)
	if err != nil {
		return fmt.Errorf("error calling rollback agent API: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("rollback agent API returned status %d: %s", resp.StatusCode, body)
	}
	return nil
}

func DefaultURL(ctx context.Context, client *kibana.Client) (string, error) {
	req := kibana.ListFleetServerHostsRequest{}
	resp, err := client.ListFleetServerHosts(ctx, req)
	if err != nil {
		return "", fmt.Errorf("unable to list fleet server hosts: %w", err)
	}

	for _, item := range resp.Items {
		if item.IsDefault {
			hostURLs := item.HostURLs
			if len(hostURLs) > 0 {
				return hostURLs[0], nil
			}
		}
	}

	return "", errors.New("unable to determine default fleet server URL")
}

func SwitchAgentToUnprivileged(ctx context.Context, client *kibana.Client, agentID string) error {
	userInfo := struct {
		Groupname string `json:"groupname"`
		Password  string `json:"password"`
		Username  string `json:"username"`
	}{
		Username:  "",
		Groupname: "",
		Password:  "",
	}
	privilegeLevelChangeReq := kibana.AgentPrivilegeLevelChangeRequest{
		UserInfo: &userInfo,
	}
	err := client.AgentPrivilegeLevelChange(ctx, agentID, privilegeLevelChangeReq)
	if err != nil {
		return fmt.Errorf("unable to change privilege level for agent with ID [%s]: %w", agentID, err)
	}
	return nil
}

// NewEnrollParams creates a new policy with monitoring logs and metrics,
// an enrollment token and returns an EnrollParams with the information to enroll
// an agent. If an error happens, it returns nil and a non-nil error.
func NewEnrollParams(ctx context.Context, client *kibana.Client) (*EnrollParams, error) {
	policyUUID := uuid.Must(uuid.NewV4()).String()
	policy := kibana.AgentPolicy{
		Name:        "test-policy-" + policyUUID,
		Namespace:   "default",
		Description: "Test policy " + policyUUID,
		MonitoringEnabled: []kibana.MonitoringEnabledOption{
			kibana.MonitoringEnabledLogs,
			kibana.MonitoringEnabledMetrics,
		},
	}

	policyResp, err := client.CreatePolicy(ctx, policy)
	if err != nil {
		return nil, fmt.Errorf("failed creating policy: %w", err)
	}

	createEnrollmentApiKeyReq := kibana.CreateEnrollmentAPIKeyRequest{
		PolicyID: policyResp.ID,
	}
	enrollmentToken, err := client.CreateEnrollmentAPIKey(ctx, createEnrollmentApiKeyReq)
	if err != nil {
		return nil, fmt.Errorf("failed creating enrollment API key: %w", err)
	}

	fleetServerURL, err := DefaultURL(ctx, client)
	if err != nil {
		return nil, fmt.Errorf("failed getting Fleet Server URL: %w", err)
	}

	return &EnrollParams{
		EnrollmentToken: enrollmentToken.APIKey,
		FleetURL:        fleetServerURL,
		PolicyID:        policyResp.ID,
	}, nil
}

// OutputPreset is a Fleet Elasticsearch output prefermance preset value.
// See https://www.elastic.co/docs/reference/fleet/es-output-settings#es-output-settings-performance-tuning-settings
type OutputPreset string

const (
	// DefaultFleetOutputID is the well-known ID of the default Fleet Elasticsearch
	// output, as defined in the Kibana Fleet plugin source:
	// x-pack/platform/plugins/shared/fleet/common/constants/output.ts
	DefaultFleetOutputID = "fleet-default-output"

	// OutputPresetLatency lowers the output flush timeout from the default 10s to 1s. Prefer it in all tests.
	OutputPresetLatency    OutputPreset = "latency"
	OutputPresetBalanced   OutputPreset = "balanced"
	OutputPresetCustom     OutputPreset = "custom"
	OutputPresetThroughput OutputPreset = "throughput"
	OutputPresetScale      OutputPreset = "scale"
)

// UpdateESOutputPreset updates the Fleet Elasticsearch output with the given ID
// to use the given preset. Use DefaultFleetOutputID to target the default output
// and OutputPresetLatency to lower the flush interval from 10s to 1s, which
// speeds up tests that poll Elasticsearch for ingested data.
//
// Call this before enrolling the agent so that the preset is in effect from the
// agent's first check-in, avoiding an extra policy revision bump mid-test.
func UpdateESOutputPreset(ctx context.Context, client *kibana.Client, outputID string, preset OutputPreset) error {
	updateBytes, err := json.Marshal(map[string]any{"preset": preset})
	if err != nil {
		return fmt.Errorf("marshaling Fleet output update: %w", err)
	}

	url := "/api/fleet/outputs/" + outputID
	resp, err := client.SendWithContext(ctx, http.MethodPut, url, nil, nil, bytes.NewReader(updateBytes))
	if err != nil {
		return fmt.Errorf("updating Fleet output %s: %w", outputID, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("updating Fleet output %s returned status %d: %s", outputID, resp.StatusCode, body)
	}

	return nil
}

// osqueryAPIVersion is the versioned-route header required by the osquery
// plugin's public API. See
// x-pack/platform/plugins/shared/osquery/common/constants.ts (API_VERSIONS.public.v1)
// in the Kibana repository.
const osqueryAPIVersion = "2023-10-31"

func osqueryAPIHeaders() http.Header {
	h := http.Header{}
	h.Set("elastic-api-version", osqueryAPIVersion)
	return h
}

// doOsqueryRequest sends a request to the osquery plugin's API and returns the
// raw response body, after checking for a 200 status. action names the call
// for error messages (e.g. "submitting osquery live query").
func doOsqueryRequest(ctx context.Context, client *kibana.Client, method, path, action string, reqBody io.Reader) ([]byte, error) {
	resp, err := client.SendWithContext(ctx, method, path, nil, osqueryAPIHeaders(), reqBody)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", action, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading %s response: %w", action, err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s returned status %d: %s", action, resp.StatusCode, body)
	}
	return body, nil
}

// OsqueryLiveQuery identifies a submitted live query: ActionID is the parent
// action ID (used to poll status), QueryActionID is the per-query action ID
// (used to fetch results).
type OsqueryLiveQuery struct {
	ActionID      string
	QueryActionID string
}

type osqueryLiveQueryCreateResponse struct {
	Data struct {
		ActionID string `json:"action_id"`
		Queries  []struct {
			ActionID string `json:"action_id"`
		} `json:"queries"`
	} `json:"data"`
}

// SubmitOsqueryLiveQuery submits a live query for the given agent via Kibana's
// osquery plugin (POST /api/osquery/live_queries), which creates a Fleet
// INPUT_ACTION with input_type "osquery" under the hood.
func SubmitOsqueryLiveQuery(ctx context.Context, client *kibana.Client, agentID, query string) (OsqueryLiveQuery, error) {
	reqBody, err := json.Marshal(map[string]any{
		"agent_ids": []string{agentID},
		"query":     query,
	})
	if err != nil {
		return OsqueryLiveQuery{}, fmt.Errorf("marshaling live query request: %w", err)
	}

	body, err := doOsqueryRequest(ctx, client, http.MethodPost, "/api/osquery/live_queries", "submitting osquery live query", bytes.NewReader(reqBody))
	if err != nil {
		return OsqueryLiveQuery{}, err
	}

	var parsed osqueryLiveQueryCreateResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return OsqueryLiveQuery{}, fmt.Errorf("unmarshaling osquery live query response: %w: %s", err, body)
	}
	if parsed.Data.ActionID == "" || len(parsed.Data.Queries) == 0 {
		return OsqueryLiveQuery{}, fmt.Errorf("osquery live query response missing action id(s): %s", body)
	}

	return OsqueryLiveQuery{
		ActionID:      parsed.Data.ActionID,
		QueryActionID: parsed.Data.Queries[0].ActionID,
	}, nil
}

type osqueryLiveQueryDetailsResponse struct {
	Data struct {
		Status string `json:"status"`
	} `json:"data"`
}

// GetOsqueryLiveQueryStatus fetches the status ("running" or "completed") of a
// previously submitted live query via GET /api/osquery/live_queries/{actionID}.
func GetOsqueryLiveQueryStatus(ctx context.Context, client *kibana.Client, actionID string) (string, error) {
	body, err := doOsqueryRequest(ctx, client, http.MethodGet, "/api/osquery/live_queries/"+actionID, "fetching osquery live query details", nil)
	if err != nil {
		return "", err
	}

	var parsed osqueryLiveQueryDetailsResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return "", fmt.Errorf("unmarshaling osquery live query details response: %w: %s", err, body)
	}
	return parsed.Data.Status, nil
}
