package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/pkg/errors"
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
func (c *Client) GetAgentByHostnameFromList(hostname string) (Agent, error) {

	agents, err := c.ListAgents()
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

// ListAgents returns the list of agents enrolled with Fleet.
func (c *Client) ListAgents() ([]Agent, error) {
	statusCode, respBody, err := c.get(context.Background(), fmt.Sprintf("%s/agents", "api/fleet"))

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
		return nil, errors.Wrap(err, "could not convert list of agents (response) to JSON")
	}

	return resp.Items, nil

}

func (c *Client) GetAgentStatus() (string, error) {
	hostname, err := os.Hostname()
	if err != nil {
		return "", nil
	}

	agent, err := c.GetAgentByHostnameFromList(hostname)
	fmt.Println(agent.Status)
	return agent.Status, nil
}

func (c *Client) UnEnrollAgent() error {
	hostname, err := os.Hostname()
	if err != nil {
		return err
	}
	agentID, err := c.GetAgentIDByHostname(hostname)
	if err != nil {
		return err
	}

	reqBody := `{"revoke": true}`
	statusCode, respBody, _ := c.post(context.Background(), fmt.Sprintf("%s/agents/%s/unenroll", "api/fleet", agentID), []byte(reqBody))
	if statusCode != 200 {
		return fmt.Errorf("could not unenroll agent; API status code = %d, response body = %s", statusCode, respBody)
	}
	return nil
}

func (c *Client) GetAgentIDByHostname(hostname string) (string, error) {
	agent, err := c.GetAgentByHostnameFromList(hostname)
	if err != nil {
		return "", err
	}
	log.WithFields(log.Fields{
		"agentId":  agent.ID,
		"hostname": hostname,
	}).Trace("Agent Id found")
	return agent.ID, nil
}
