// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package fleet

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/elastic/elastic-agent-libs/kibana"
)

// AgentByHostnameFromList get an agent by the local_metadata.host.name property, reading from the agents list
func AgentByHostnameFromList(client *kibana.Client, hostname string) (*kibana.AgentExisting, error) {
	listAgentsResp, err := client.ListAgents(context.Background(), kibana.ListAgentsRequest{})
	if err != nil {
		return nil, err
	}

	for _, item := range listAgentsResp.Items {
		agentHostname := item.LocalMetadata.Host.Hostname
		if agentHostname == hostname {
			return &item, nil
		}
	}

	return nil, fmt.Errorf("unable to find agent with hostname [%s]", hostname)
}

func AgentStatus(client *kibana.Client) (string, error) {
	// TODO: fix me: this does not work if FQDN is enabled
	hostname, err := os.Hostname()
	if err != nil {
		return "", err
	}

	agent, err := AgentByHostnameFromList(client, hostname)
	if err != nil {
		return "", err
	}

	return agent.Status, nil
}

func AgentVersion(client *kibana.Client) (string, error) {
	hostname, err := os.Hostname()
	if err != nil {
		return "", err
	}

	agent, err := AgentByHostnameFromList(client, hostname)
	if err != nil {
		return "", err
	}

	return agent.Agent.Version, err
}

func UnenrollAgent(client *kibana.Client) error {
	hostname, err := os.Hostname()
	if err != nil {
		return err
	}
	agentID, err := AgentIDByHostname(client, hostname)
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

func AgentIDByHostname(client *kibana.Client, hostname string) (string, error) {
	agent, err := AgentByHostnameFromList(client, hostname)
	if err != nil {
		return "", err
	}
	return agent.Agent.ID, nil
}

func UpgradeAgent(client *kibana.Client, version string) error {
	// TODO: fix me: this does not work if FQDN is enabled
	hostname, err := os.Hostname()
	if err != nil {
		return err
	}
	agentID, err := AgentIDByHostname(client, hostname)
	if err != nil {
		return err
	}

	upgradeAgentReq := kibana.UpgradeAgentRequest{
		ID:      agentID,
		Version: version,
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
