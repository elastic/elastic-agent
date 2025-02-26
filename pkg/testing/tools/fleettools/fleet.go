// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package fleettools

import (
	"context"
	"errors"
	"fmt"
	"github.com/elastic/elastic-agent-libs/kibana"
	"github.com/gofrs/uuid/v5"
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
