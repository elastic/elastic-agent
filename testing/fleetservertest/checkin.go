// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package fleetservertest

import (
	"fmt"
	"strings"
	"text/template"
)

// TmplPolicy is all the data used to create a policy. Therefore, all the properties
// should be populated with valid JSON without the surrounding double quotes.
// Check the actionPolicyChangeFakeComponentTmpl for details.
type TmplPolicy struct {
	AgentID  string
	PolicyID string
	// FleetHosts should be a JSON array without the square brackets:
	// - `"host1", "host2"`
	// - `"host"`
	FleetHosts string
	// AddFleetProxyURL bool
	FleetProxyURL *string
	SourceURI     string
	CreatedAt     string
	Output        struct {
		APIKey string
		Hosts  string
		Type   string
	}
}

// NewCheckinResponse returns a valid JSON encoded checkin response with
// the provided actions.
func NewCheckinResponse(ackToken string, actions ...string) string {
	return fmt.Sprintf(checkinResponseJSON,
		ackToken, fmt.Sprintf("[%s]", strings.Join(actions, ",")))
}

// NewEmptyPolicy returns an policy without any input and monitoring disabled.
func NewEmptyPolicy(data TmplPolicy) (string, error) {
	t := template.Must(template.New("policyEmpryTmpl").
		Parse(policyEmpryTmpl))

	buf := &strings.Builder{}
	err := t.Execute(buf, data)
	if err != nil {
		return "", fmt.Errorf("failed building action: %w", err)
	}

	return buf.String(), nil
}

type AckableAction struct {
	ActionID string
	acked    bool
	data     string
}

func NewActionWithEmptyPolicyChange(actionID string, data TmplPolicy) (AckableAction, error) {
	policy, err := NewEmptyPolicy(data)
	if err != nil {
		return AckableAction{}, fmt.Errorf("could not build policy: %w", err)
	}

	return NewAction(ActionTmpl{
		AgentID:  data.AgentID,
		Data:     policy,
		ActionID: actionID,
		Type:     "POLICY_CHANGE",
	})
}

const actionTemplate = `{
      "agent_id": "{{.AgentID}}",
      "created_at": "2023-05-31T11:37:50.607Z",
      "data": {{.Data}},
      "id": "{{.ActionID}}",
      "input_type": "",
      "type": "{{.Type}}"
    }`

func NewAction(data ActionTmpl) (AckableAction, error) {
	t := template.Must(template.New("actionTemplate").
		Parse(actionTemplate))

	buf := &strings.Builder{}
	err := t.Execute(buf, data)
	if err != nil {
		return AckableAction{}, fmt.Errorf("failed executing actionTemplate: %w", err)
	}

	return AckableAction{
		ActionID: data.ActionID,
		data:     buf.String(),
	}, nil
}

// NewActionPolicyChangeWithFakeComponent returns a AckableAction where
// the policy, AckableAction.data, contains one single integration. The
// integration uses the fake component. All variable data in the policy
// comes from the data parameter.
func NewActionPolicyChangeWithFakeComponent(actionID string, data TmplPolicy) (AckableAction, error) {
	t := template.Must(template.New("actionPolicyChangeFakeComponentTmpl").
		Parse(actionPolicyChangeFakeComponentTmpl))

	buf := &strings.Builder{}
	err := t.Execute(buf, data)
	if err != nil {
		return AckableAction{}, fmt.Errorf("failed building action: %w", err)
	}

	return NewAction(ActionTmpl{
		AgentID:  data.AgentID,
		ActionID: actionID,
		Data:     buf.String(),
		Type:     "POLICY_CHANGE",
	})
}

const (
	checkinResponseJSON = `
{
  "ack_token": "%s",
  "action": "checkin",
  "actions": %s
}`

	actionPolicyChangeFakeComponentTmpl = `
    {
        "policy": {
          "agent": {
            "download": {
              "sourceURI": "{{.SourceURI}}"
            },
            "monitoring": {
              "namespace": "default",
              "use_output": "default",
              "enabled": true,
              "logs": true,
              "metrics": true
            },
            "features": {},
            "protection": {
              "enabled": false,
              "uninstall_token_hash": "lORSaDIQq4nglUMJwWjKrwexj4IDRJA+FtoQeeqKH/I=",
              "signing_key": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEQ9BPoHUCyLyElVpfwvKeFdUt6U9wBb+QlZNf4cy5eAwK9Xh4D8fClgciPeRs3j62i6IEeGyvOs9U3+fElyUigg=="
            }
          },
          "fleet": {
            "hosts": [{{.FleetHosts}}]
          },
          "id": "{{.PolicyID}}",
          "inputs": [
            {
              "id": "fake-input",
              "revision": 1,
              "name": "fake-input",
              "type": "fake-input",
              "data_stream": {
                "namespace": "default"
              },
              "use_output": "default",
              "package_policy_id": "{{.PolicyID}}",
              "streams": [],
              "meta": {
                "package": {
                  "name": "fake-input",
                  "version": "0.0.1"
                }
              }
            }
          ],
          "output_permissions": {
            "default": {}
          },
          "outputs": {
            "default": {
              "api_key": "{{.Output.APIKey}}",
              "hosts": [{{.Output.Hosts}}],
              "type": "{{.Output.Type}}"
            }
          },
          "revision": 2,
          "secret_references": [],
          "signed": {
            "data": "eyJpZCI6IjI0ZTRkMDMwLWZmYTctMTFlZC1iMDQwLTlkZWJhYTVmZWNiOCIsImFnZW50Ijp7InByb3RlY3Rpb24iOnsiZW5hYmxlZCI6ZmFsc2UsInVuaW5zdGFsbF90b2tlbl9oYXNoIjoibE9SU2FESVFxNG5nbFVNSndXaktyd2V4ajRJRFJKQStGdG9RZWVxS0gvST0iLCJzaWduaW5nX2tleSI6Ik1Ga3dFd1lIS29aSXpqMENBUVlJS29aSXpqMERBUWNEUWdBRVE5QlBvSFVDeUx5RWxWcGZ3dktlRmRVdDZVOXdCYitRbFpOZjRjeTVlQXdLOVhoNEQ4ZkNsZ2NpUGVSczNqNjJpNklFZUd5dk9zOVUzK2ZFbHlVaWdnPT0ifX19",
            "signature": "MEUCIQCfS6wPj/AvfFA79dwKATnvyFl/ZeyA8eKOLHg1XuA9NgIgNdhjIT+G/GZFqsVoWk5jThONhpqPhfiHLE5OkTdrwT0="
          }
        }
      }`

	policyEmpryTmpl = `
    {
        "policy": {
          "agent": {
            "download": {
              "sourceURI": "{{.SourceURI}}"
            },
            "monitoring": {
              "namespace": "default",
              "use_output": "default",
              "enabled": false,
              "logs": false,
              "metrics": false
            },
            "features": {},
            "protection": {
              "enabled": false,
              "uninstall_token_hash": "lORSaDIQq4nglUMJwWjKrwexj4IDRJA+FtoQeeqKH/I=",
              "signing_key": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEQ9BPoHUCyLyElVpfwvKeFdUt6U9wBb+QlZNf4cy5eAwK9Xh4D8fClgciPeRs3j62i6IEeGyvOs9U3+fElyUigg=="
            }
          },
          "fleet": {
            {{ if ne .FleetProxyURL nil }}
            "proxy_url": "{{.FleetProxyURL}}",
            {{ end }}
            "hosts": [{{.FleetHosts}}]
          },
          "id": "{{.PolicyID}}",
          "inputs": [],
          "output_permissions": {
            "default": {}
          },
          "outputs": {
            "default": {
              "api_key": "{{.Output.APIKey}}",
              "hosts": [{{.Output.Hosts}}],
              "type": "{{.Output.Type}}"
            }
          },
          "revision": 2,
          "secret_references": [],
          "signed": {
            "data": "eyJpZCI6IjI0ZTRkMDMwLWZmYTctMTFlZC1iMDQwLTlkZWJhYTVmZWNiOCIsImFnZW50Ijp7InByb3RlY3Rpb24iOnsiZW5hYmxlZCI6ZmFsc2UsInVuaW5zdGFsbF90b2tlbl9oYXNoIjoibE9SU2FESVFxNG5nbFVNSndXaktyd2V4ajRJRFJKQStGdG9RZWVxS0gvST0iLCJzaWduaW5nX2tleSI6Ik1Ga3dFd1lIS29aSXpqMENBUVlJS29aSXpqMERBUWNEUWdBRVE5QlBvSFVDeUx5RWxWcGZ3dktlRmRVdDZVOXdCYitRbFpOZjRjeTVlQXdLOVhoNEQ4ZkNsZ2NpUGVSczNqNjJpNklFZUd5dk9zOVUzK2ZFbHlVaWdnPT0ifX19",
            "signature": "MEUCIQCfS6wPj/AvfFA79dwKATnvyFl/ZeyA8eKOLHg1XuA9NgIgNdhjIT+G/GZFqsVoWk5jThONhpqPhfiHLE5OkTdrwT0="
          }
        }
      }`
)
