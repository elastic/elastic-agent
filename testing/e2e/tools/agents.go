package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/avast/retry-go"
	log "github.com/sirupsen/logrus"
)

// PolicyOutput holds the needed data to manage the output API keys
type PolicyOutput struct {
	// API key the Elastic Agent uses to authenticate with elasticsearch
	APIKey string `json:"api_key"`

	// ID of the API key the Elastic Agent uses to authenticate with elasticsearch
	APIKeyID string `json:"api_key_id"`

	// The policy output permissions hash
	PermissionsHash string `json:"permissions_hash"`

	// API keys to be invalidated on next agent ack
	ToRetireAPIKeyIds []ToRetireAPIKeyIdsItems `json:"to_retire_api_key_ids,omitempty"`

	// Type is the output type. Currently only Elasticsearch is supported.
	Type string `json:"type"`
}

type ToRetireAPIKeyIdsItems struct {

	// API Key identifier
	ID string `json:"id,omitempty"`

	// Date/time the API key was retired
	RetiredAt string `json:"retired_at,omitempty"`
}

type Agent struct {
	ID             string `json:"id"`
	PolicyID       string `json:"policy_id"`
	PolicyRevision int    `json:"policy_revision,omitempty"`
	DefaultAPIKey  string `json:"default_api_key"`
	LocalMetadata  struct {
		Host struct {
			Name     string `json:"name"`
			HostName string `json:"hostname"`
		} `json:"host"`
		OS struct {
			Family   string `json:"family"`
			Full     string `json:"full"`
			Platform string `json:"platform"`
		} `json:"os"`
		Elastic struct {
			Agent struct {
				Version  string `json:"version"`
				Snapshot bool   `json:"snapshot"`
			} `json:"agent"`
		} `json:"elastic"`
	} `json:"local_metadata"`
	Status  string                   `json:"status"`
	Outputs map[string]*PolicyOutput `json:"outputs,omitempty"`
}

// GetAgentByHostnameFromList get an agent by the local_metadata.host.name property, reading from the agents list
func (c *Client) GetAgentByHostnameFromList(ctx context.Context, hostname string) (Agent, error) {

	agents, err := c.ListAgents(ctx)
	if err != nil {
		return Agent{}, err
	}

	for _, agent := range agents {
		agentHostname := agent.LocalMetadata.Host.Name
		// a hostname has an agentID by status
		if agentHostname == hostname {
			log.WithFields(log.Fields{
				"agent": agent,
			}).Trace("Agent found")
			return agent, nil
		}
	}

	return Agent{}, nil
}

func (c *Client) ListAgents(ctx context.Context) ([]Agent, error) {
	var agents []Agent
	err := retry.Do(func() error {
		var err error
		agents, err = c.listAgents(ctx)
		return err
	},
		retry.Attempts(2),
		retry.Delay(5*time.Second),
		retry.OnRetry(func(n uint, err error) {
			log.Warnf("Failed to list agents. Retrying... Error: %v", err)
		}),
	)
	return agents, err
}

// ListAgents returns the list of agents enrolled with Fleet.
func (c *Client) listAgents(ctx context.Context) ([]Agent, error) {
	statusCode, respBody, err := c.get(ctx, fmt.Sprintf("%s/agents", "api/fleet"))

	if err != nil {
		log.WithFields(log.Fields{
			"body":  string(respBody),
			"error": err,
		}).Error("Could not get Fleet's online agents")
		return nil, err
	}

	if statusCode != 200 {
		log.WithFields(log.Fields{
			"body":       string(respBody),
			"error":      err,
			"statusCode": statusCode,
		}).Error("Could not get Fleet's online agents")

		return nil, err
	}

	var resp struct {
		Items []Agent `json:"items"`
	}

	if err := json.Unmarshal(respBody, &resp); err != nil {

		return nil, fmt.Errorf("could not convert list of agents (response) to JSON. %w", err)
	}

	return resp.Items, nil

}

func (c *Client) GetAgentStatus(ctx context.Context) (string, error) {
	hostname, err := os.Hostname()
	if err != nil {
		return "", err
	}

	agent, err := c.GetAgentByHostnameFromList(ctx, hostname)
	return agent.Status, err
}

func (c *Client) GetAgentVersion(ctx context.Context) (string, error) {
	hostname, err := os.Hostname()
	if err != nil {
		return "", err
	}

	agent, err := c.GetAgentByHostnameFromList(ctx, hostname)
	return agent.LocalMetadata.Elastic.Agent.Version, err
}

func (c *Client) UnEnrollAgent(ctx context.Context) error {
	hostname, err := os.Hostname()
	if err != nil {
		return err
	}
	agentID, err := c.GetAgentIDByHostname(ctx, hostname)
	if err != nil {
		return err
	}

	reqBody := `{"revoke": true}`
	statusCode, respBody, _ := c.post(ctx, fmt.Sprintf("%s/agents/%s/unenroll", "api/fleet", agentID), []byte(reqBody))
	if statusCode != 200 {
		return fmt.Errorf("could not unenroll agent; API status code = %d, response body = %s", statusCode, respBody)
	}
	return nil
}

func (c *Client) GetAgentIDByHostname(ctx context.Context, hostname string) (string, error) {
	agent, err := c.GetAgentByHostnameFromList(ctx, hostname)
	if err != nil {
		return "", err
	}
	return agent.ID, nil
}

func (c *Client) UpgradeAgent(ctx context.Context, version string) error {
	hostname, err := os.Hostname()
	if err != nil {
		return err
	}
	agentID, err := c.GetAgentIDByHostname(ctx, hostname)
	if err != nil {
		return err
	}

	reqBody := `{"version":"` + version + `"}`
	statusCode, respBody, err := c.post(ctx, fmt.Sprintf("%s/agents/%s/upgrade", "api/fleet", agentID), []byte(reqBody))
	if statusCode != 200 {
		log.WithFields(log.Fields{
			"body":           string(respBody),
			"desiredVersion": version,
			"error":          err,
			"statusCode":     statusCode,
		}).Error("Could not upgrade agent to version")

		return err
	}
	return nil
}
