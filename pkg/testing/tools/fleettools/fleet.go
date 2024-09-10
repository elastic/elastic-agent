// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package fleettools

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/gofrs/uuid/v5"

	"github.com/elastic/elastic-agent-libs/kibana"
)

type EnrollParams struct {
	EnrollmentToken string `json:"api_key"`
	FleetURL        string `json:"fleet_url"`
	PolicyID        string `json:"policy_id"`
}

// GetAgentByPolicyIDAndHostnameFromList get an agent by the local_metadata.host.name property, reading from the agents list
func GetAgentByPolicyIDAndHostnameFromList(ctx context.Context, client *kibana.Client, policyID, hostname string) (*kibana.AgentExisting, error) {
	listAgentsResp, err := client.ListAgents(ctx, kibana.ListAgentsRequest{})
	if err != nil {
		return nil, err
	}

	var agentHostnames []string
	hostnameAgents := make([]*kibana.AgentExisting, 0)
	for i, item := range listAgentsResp.Items {
		agentHostname := item.LocalMetadata.Host.Hostname
		agentPolicyID := item.PolicyID

		if strings.EqualFold(agentHostname, hostname) && agentPolicyID == policyID {
			hostnameAgents = append(hostnameAgents, &listAgentsResp.Items[i])
		}
	}

	if len(hostnameAgents) == 0 {
		return nil, fmt.Errorf("unable to find agent with hostname [%s] for policy [%s]. Found: %v",
			hostname, policyID, agentHostnames)
	}

	if len(hostnameAgents) > 1 {
		return nil, fmt.Errorf("found %d agents with hostname [%s]; expected to find only one", len(hostnameAgents), hostname)
	}

	return hostnameAgents[0], nil
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
