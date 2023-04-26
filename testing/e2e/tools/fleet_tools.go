package tools

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/Jeffail/gabs/v2"
	"github.com/avast/retry-go"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
)

type Policy struct {
	ID                   string `json:"id,omitempty"`
	Name                 string `json:"name"`
	Description          string `json:"description"`
	Namespace            string `json:"namespace"`
	IsDefault            bool   `json:"is_default"`
	IsManaged            bool   `json:"is_managed"`
	IsDefaultFleetServer bool   `json:"is_default_fleet_server"`
	AgentsCount          int    `json:"agents"` // Number of agents connected to Policy
	Status               string `json:"status"`
}

type EnrollmentAPIKey struct {
	Active   bool   `json:"active"`
	APIKey   string `json:"api_key"`
	APIKeyID string `json:"api_key_id"`
	ID       string `json:"id"`
	Name     string `json:"name"`
	PolicyID string `json:"policy_id"`
}

func (c *Client) CreatePolicy(ctx context.Context) (Policy, error) {
	var policy Policy
	err := retry.Do(
		func() error {
			var err error
			policy, err = c.createPolicy(ctx)
			return err
		},
		retry.Attempts(3),
		retry.OnRetry(func(n uint, err error) {
			log.Warnf("Failed to create policy. Retrying... Error: %v", err)
		}),
	)
	return policy, err
}

func (c *Client) createPolicy(ctx context.Context) (Policy, error) {
	policyUUID := uuid.New().String()

	reqBody := `{
		"description": "Test policy ` + policyUUID + `",
		"namespace": "default",
		"monitoring_enabled": ["logs", "metrics"],
		"name": "test-policy-` + policyUUID + `"
	}`

	statusCode, respBody, _ := c.post(ctx, fmt.Sprintf("%s/agent_policies", "api/fleet"), []byte(reqBody))

	jsonParsed, err := gabs.ParseJSON(respBody)

	if err != nil {
		log.WithFields(log.Fields{
			"error":        err,
			"responseBody": jsonParsed,
		}).Error("Could not parse get response into JSON")
		return Policy{}, err
	}

	if statusCode != 200 {
		return Policy{}, fmt.Errorf("could not create Fleet's policy, unhandled server error (%d)", statusCode)
	}

	if err != nil {
		return Policy{}, fmt.Errorf("could not create Fleet's policy. %w", err)
	}

	var resp struct {
		Item Policy `json:"item"`
	}

	if err := json.Unmarshal(respBody, &resp); err != nil {

		return Policy{}, fmt.Errorf("unable to convert list of new policy to JSON. %w", err)
	}

	return resp.Item, nil
}

func (c *Client) CreateEnrollmentAPIKey(ctx context.Context, policy Policy) (EnrollmentAPIKey, error) {
	var apiKey EnrollmentAPIKey
	err := retry.Do(
		func() error {
			var err error
			apiKey, err = c.createEnrollmentAPIKey(ctx, policy)
			return err
		},
		retry.Attempts(3),
		retry.OnRetry(func(n uint, err error) {
			log.Warnf("Failed to create enrollment api key. Retrying... Error: %v", err)
		}),
	)
	return apiKey, err
}

func (c *Client) createEnrollmentAPIKey(ctx context.Context, policy Policy) (EnrollmentAPIKey, error) {

	reqBody := `{"policy_id": "` + policy.ID + `"}`

	statusCode, respBody, _ := c.post(ctx, fmt.Sprintf("%s/enrollment_api_keys", "api/fleet"), []byte(reqBody))
	if statusCode != 200 {
		jsonParsed, err := gabs.ParseJSON(respBody)
		log.WithFields(log.Fields{
			"body":       jsonParsed,
			"reqBody":    reqBody,
			"error":      err,
			"statusCode": statusCode,
		}).Error("Could not create enrollment api key")

		return EnrollmentAPIKey{}, err
	}

	var resp struct {
		Enrollment EnrollmentAPIKey `json:"item"`
	}

	if err := json.Unmarshal(respBody, &resp); err != nil {
		return EnrollmentAPIKey{}, fmt.Errorf("unable to convert enrollment response to JSON. %w", err)
	}

	return resp.Enrollment, nil
}
