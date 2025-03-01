// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package fleettools

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"

	"github.com/gofrs/uuid/v5"

	"github.com/elastic/elastic-agent-libs/kibana"
)

type EnrollParams struct {
	EnrollmentToken string `json:"api_key"`
	FleetURL        string `json:"fleet_url"`
	PolicyID        string `json:"policy_id"`
}

func extractError(result []byte) error {
	var kibanaResult struct {
		Message    string
		Attributes struct {
			Objects []struct {
				ID    string
				Error struct {
					Message string
				}
			}
		}
	}
	if err := json.Unmarshal(result, &kibanaResult); err != nil {
		return fmt.Errorf("error extracting JSON for error response: %w", err)
	}
	var errs []error
	if kibanaResult.Message != "" {
		for _, err := range kibanaResult.Attributes.Objects {
			errs = append(errs, fmt.Errorf("id: %s, message: %s", err.ID, err.Error.Message))
		}
		if len(errs) == 0 {
			return fmt.Errorf("%s", kibanaResult.Message)
		}
		return fmt.Errorf("%s: %w", kibanaResult.Message, errors.Join(errs...))

	}
	return nil
}

// GetAgentByPolicyIDAndHostnameFromList get an agent by the local_metadata.host.name property, reading from the agents list
func GetAgentByPolicyIDAndHostnameFromList(ctx context.Context, client *kibana.Client, policyID, hostname string) (*kibana.AgentExisting, error) {
	params := url.Values{}
	params.Add("kuery", fmt.Sprintf(`local_metadata.host.name:"%s" and policy_id:"%s" and active:true`, hostname, policyID))

	resp, err := client.Connection.SendWithContext(ctx, http.MethodGet, "/api/fleet/agents", params, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("error calling list agents API: %w", err)
	}
	defer resp.Body.Close()

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, extractError(b)
	}
	var r kibana.ListAgentsResponse
	err = json.Unmarshal(b, &r)
	if err != nil {
		return nil, fmt.Errorf("unmarshalling response json: %w", err)
	}

	if len(r.Items) == 0 {
		return nil, fmt.Errorf("unable to find agent with hostname [%s] for policy [%s]",
			hostname, policyID)
	}

	if len(r.Items) > 1 {
		return nil, fmt.Errorf("found %d agents with hostname [%s] for policy [%s]; expected to find only one, response:\n%s", len(r.Items), hostname, policyID, b)
	}

	return &r.Items[0], nil
}

func GetAgentIDByHostname(ctx context.Context, client *kibana.Client, policyID, hostname string) (string, error) {
	agent, err := GetAgentByPolicyIDAndHostnameFromList(ctx, client, policyID, hostname)
	if err != nil {
		return "", err
	}
	return agent.Agent.ID, nil
}

func GetAgentStatus(ctx context.Context, client *kibana.Client, policyID string) (string, error) {
	hostname, err := os.Hostname()
	if err != nil {
		return "", err
	}

	agent, err := GetAgentByPolicyIDAndHostnameFromList(ctx, client, policyID, hostname)
	if err != nil {
		return "", err
	}

	return agent.Status, nil
}

func GetAgentVersion(ctx context.Context, client *kibana.Client, policyID string) (string, error) {
	hostname, err := os.Hostname()
	if err != nil {
		return "", err
	}

	agent, err := GetAgentByPolicyIDAndHostnameFromList(ctx, client, policyID, hostname)
	if err != nil {
		return "", err
	}

	return agent.Agent.Version, err
}

func UnEnrollAgent(ctx context.Context, client *kibana.Client, policyID string) error {
	hostname, err := os.Hostname()
	if err != nil {
		return err
	}
	agentID, err := GetAgentIDByHostname(ctx, client, policyID, hostname)
	if err != nil {
		return err
	}

	unEnrollAgentReq := kibana.UnEnrollAgentRequest{
		ID:     agentID,
		Revoke: true,
	}
	_, err = client.UnEnrollAgent(ctx, unEnrollAgentReq)
	if err != nil {
		return fmt.Errorf("unable to unenroll agent with ID [%s]: %w", agentID, err)
	}

	return nil
}

func UpgradeAgent(ctx context.Context, client *kibana.Client, policyID, version string, force bool) error {
	// TODO: fix me: this does not work if FQDN is enabled
	hostname, err := os.Hostname()
	if err != nil {
		return err
	}
	agentID, err := GetAgentIDByHostname(ctx, client, policyID, hostname)
	if err != nil {
		return err
	}

	upgradeAgentReq := kibana.UpgradeAgentRequest{
		ID:      agentID,
		Version: version,
		Force:   force,
	}
	_, err = client.UpgradeAgent(ctx, upgradeAgentReq)
	if err != nil {
		return fmt.Errorf("unable to upgrade agent with ID [%s]: %w", agentID, err)
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
