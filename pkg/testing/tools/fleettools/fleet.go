// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package fleettools

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/elastic/elastic-agent-libs/kibana"
)

// GetAgentByPolicyIDAndHostnameFromList get an agent by the local_metadata.host.name property, reading from the agents list
func GetAgentByPolicyIDAndHostnameFromList(client *kibana.Client, policyID, hostname string) (*kibana.AgentExisting, error) {
	listAgentsResp, err := client.ListAgents(context.Background(), kibana.ListAgentsRequest{})
	if err != nil {
		return nil, err
	}

	hostnameAgents := make([]*kibana.AgentExisting, 0)
	for i, item := range listAgentsResp.Items {
		agentHostname := item.LocalMetadata.Host.Hostname
		agentPolicyID := item.PolicyID

		if agentHostname == hostname && agentPolicyID == policyID {
			hostnameAgents = append(hostnameAgents, &listAgentsResp.Items[i])
		}
	}

	if len(hostnameAgents) == 0 {
		return nil, fmt.Errorf("unable to find agent with hostname [%s]", hostname)
	}

	if len(hostnameAgents) > 1 {
		return nil, fmt.Errorf("found %d agents with hostname [%s]; expected to find only one", len(hostnameAgents), hostname)
	}

	return hostnameAgents[0], nil
}

func GetAgentIDByHostname(client *kibana.Client, policyID, hostname string) (string, error) {
	agent, err := GetAgentByPolicyIDAndHostnameFromList(client, policyID, hostname)
	if err != nil {
		return "", err
	}
	return agent.Agent.ID, nil
}

func GetAgentStatus(client *kibana.Client, policyID string) (string, error) {
	hostname, err := os.Hostname()
	if err != nil {
		return "", err
	}

	agent, err := GetAgentByPolicyIDAndHostnameFromList(client, policyID, hostname)
	if err != nil {
		return "", err
	}

	return agent.Status, nil
}

func GetAgentVersion(client *kibana.Client, policyID string) (string, error) {
	hostname, err := os.Hostname()
	if err != nil {
		return "", err
	}

	agent, err := GetAgentByPolicyIDAndHostnameFromList(client, policyID, hostname)
	if err != nil {
		return "", err
	}

	return agent.Agent.Version, err
}

func UnEnrollAgent(client *kibana.Client, policyID string) error {
	hostname, err := os.Hostname()
	if err != nil {
		return err
	}
	agentID, err := GetAgentIDByHostname(client, policyID, hostname)
	if err != nil {
		return err
	}

	unEnrollAgentReq := kibana.UnEnrollAgentRequest{
		ID:     agentID,
		Revoke: true,
	}
	_, err = client.UnEnrollAgent(context.Background(), unEnrollAgentReq)
	if err != nil {
		return fmt.Errorf("unable to unenroll agent with ID [%s]: %w", agentID, err)
	}

	return nil
}

func UpgradeAgent(client *kibana.Client, policyID, version string, force bool) error {
	// TODO: fix me: this does not work if FQDN is enabled
	hostname, err := os.Hostname()
	if err != nil {
		return err
	}
	agentID, err := GetAgentIDByHostname(client, policyID, hostname)
	if err != nil {
		return err
	}

	upgradeAgentReq := kibana.UpgradeAgentRequest{
		ID:      agentID,
		Version: version,
		Force:   force,
	}
	_, err = client.UpgradeAgent(context.Background(), upgradeAgentReq)
	if err != nil {
		return fmt.Errorf("unable to upgrade agent with ID [%s]: %w", agentID, err)
	}

	return nil
}

func DefaultURL(client *kibana.Client) (string, error) {
	req := kibana.ListFleetServerHostsRequest{}
	resp, err := client.ListFleetServerHosts(context.Background(), req)
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
