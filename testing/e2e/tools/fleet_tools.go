package tools

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/Jeffail/gabs/v2"
	"github.com/google/uuid"
	"github.com/pkg/errors" //nolint:gomodguard //for tests
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

func (c *Client) CreatePolicy() (Policy, error) {
	policyUUID := uuid.New().String()

	reqBody := `{
		"description": "Test policy ` + policyUUID + `",
		"namespace": "default",
		"monitoring_enabled": ["logs", "metrics"],
		"name": "test-policy-` + policyUUID + `"
	}`

	statusCode, respBody, _ := c.post(context.Background(), fmt.Sprintf("%s/agent_policies", "api/fleet"), []byte(reqBody))

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
		return Policy{}, errors.Wrap(err, "Could not create Fleet's policy")
	}

	var resp struct {
		Item Policy `json:"item"`
	}

	if err := json.Unmarshal(respBody, &resp); err != nil {
		return Policy{}, errors.Wrap(err, "Unable to convert list of new policy to JSON")
	}

	return resp.Item, nil
}

func (c *Client) CreateEnrollmentAPIKey(policy Policy) (EnrollmentAPIKey, error) {

	reqBody := `{"policy_id": "` + policy.ID + `"}`

	statusCode, respBody, _ := c.post(context.Background(), fmt.Sprintf("%s/enrollment_api_keys", "api/fleet"), []byte(reqBody))
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
		return EnrollmentAPIKey{}, errors.Wrap(err, "Unable to convert enrollment response to JSON")
	}

	return resp.Enrollment, nil
}
