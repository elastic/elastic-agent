// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package tools

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-libs/kibana"
	"github.com/elastic/elastic-agent/pkg/control/v2/client"
	"github.com/elastic/elastic-agent/pkg/control/v2/cproto"
)

// GetAgentByID get an agent by the local_metadata.host.name property, reading from the agents list
func GetAgentByID(client *kibana.Client, agentID string) (*kibana.AgentExisting, error) {
	listAgentsResp, err := client.ListAgents(context.Background(), kibana.ListAgentsRequest{})
	if err != nil {
		return nil, err
	}

	agents := make([]*kibana.AgentExisting, 0)
	for i, item := range listAgentsResp.Items {
		if agentID == item.Agent.ID {
			agents = append(agents, &listAgentsResp.Items[i])
		}
	}

	if len(agents) == 0 {
		return nil, fmt.Errorf("unable to find agent with ID [%s]", agentID)
	}

	if len(agents) > 1 {
		return nil, fmt.Errorf("found %d agents with ID [%s]; expected to find only one", len(agents), agentID)
	}

	return agents[0], nil
}

func GetAgentStatus(client *kibana.Client, agentID string) (string, error) {
	agent, err := GetAgentByID(client, agentID)
	if err != nil {
		return "", err
	}

	return agent.Status, nil
}

func GetAgentVersion(client *kibana.Client, agentID string) (string, error) {
	agent, err := GetAgentByID(client, agentID)
	if err != nil {
		return "", err
	}

	return agent.Agent.Version, err
}

func UnEnrollAgent(client *kibana.Client, agentID string) error {
	unEnrollAgentReq := kibana.UnEnrollAgentRequest{
		ID:     agentID,
		Revoke: true,
	}
	_, err := client.UnEnrollAgent(context.Background(), unEnrollAgentReq)
	if err != nil {
		return fmt.Errorf("unable to unenroll agent with ID [%s]: %w", agentID, err)
	}

	return nil
}

func UpgradeAgent(client *kibana.Client, agentID, version string) error {
	upgradeAgentReq := kibana.UpgradeAgentRequest{
		ID:      agentID,
		Version: version,
	}
	_, err := client.UpgradeAgent(context.Background(), upgradeAgentReq)
	if err != nil {
		return fmt.Errorf("unable to upgrade agent with ID [%s]: %w", agentID, err)
	}

	return nil
}

func GetDefaultFleetServerURL(client *kibana.Client) (string, error) {
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

	return "", errors.New("unable to determine default fleet server host")
}

func WaitForAgent(ctx context.Context, t *testing.T, c client.Client) {
	require.Eventually(t, func() bool {
		err := c.Connect(ctx)
		if err != nil {
			t.Logf("connecting client to agent: %v", err)
			return false
		}
		defer c.Disconnect()
		state, err := c.State(ctx)
		if err != nil {
			t.Logf("error getting the agent state: %v", err)
			return false
		}
		t.Logf("agent state: %+v", state)
		return state.State == cproto.State_HEALTHY
	}, 2*time.Minute, 10*time.Second, "Agent never became healthy")
}
