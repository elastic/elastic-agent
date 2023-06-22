// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package fleetservertest

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi"
)

func ExampleNewServer_status() {
	apiKey := "aAPIKey"
	ts := NewServer(&Handlers{
		APIKey:   apiKey,
		StatusFn: NewHandlerStatusHealth(),
	}, Data{})

	r, err := http.NewRequest(http.MethodGet, ts.URL+PathStatus, nil)
	if err != nil {
		panic(fmt.Sprintf("could not create new request to fleet-test-server: %v", err))
	}
	r.Header.Set(NewAuthorizationHeader(apiKey))

	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		panic(fmt.Sprintf("could not make request to fleet-test-server: %v", err))
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		if err != nil {
			panic(fmt.Sprintf("could not read response: %v", err))
		}
	}
	fmt.Printf("%s", body)

	// Output:
	// {"name":"fleet-server","status":"HEALTHY"}
}

func ExampleNewServer_checkin() {
	agentID := "agentID"

	ts := NewServer(&Handlers{
		CheckinFn: NewHandlerCheckin(agentID),
	}, Data{})

	cmd := fleetapi.NewCheckinCmd(
		agentInfo(agentID), sender{url: ts.URL, path: NewPathCheckin(agentID)})
	resp, _, err := cmd.Execute(context.Background(), &fleetapi.CheckinRequest{})
	if err != nil {
		panic(fmt.Sprintf("failed executing checkin: %v", err))
	}

	fmt.Println(resp.Actions)

	// Output:
	// [action_id: policy:24e4d030-ffa7-11ed-b040-9debaa5fecb8:2:1, type: POLICY_CHANGE]
}

func ExampleNewHandlerEnroll() {
	nowStr := "2009-11-10T23:00:00+00:00"
	now, err := time.Parse(time.RFC3339, nowStr)
	if err != nil {
		panic(fmt.Sprintf("could not parse %q as time: %v", nowStr, err))
	}
	timeNow = func() time.Time { return now }

	agentID := "agentID"
	policyID := "policyID"
	enrollAPIKey := "enrollAPIKey"
	apiKey := APIKey{
		ID:  "apiKeyID",
		Key: "apiKeyKey",
	}

	ts := NewServer(&Handlers{
		EnrollFn: NewHandlerEnroll(agentID, policyID, apiKey),
	}, Data{})

	cmd := fleetapi.NewEnrollCmd(sender{url: ts.URL, path: NewPathCheckin(agentID)})
	resp, err := cmd.Execute(context.Background(), &fleetapi.EnrollRequest{
		EnrollAPIKey: enrollAPIKey,
		Type:         "PERMANENT",
		Metadata: fleetapi.Metadata{
			Local: &info.ECSMeta{
				Elastic: &info.ElasticECSMeta{Agent: &info.AgentECSMeta{
					ID: "wrongAgentID",
				}},
			},
		},
	})
	if err != nil {
		panic(fmt.Sprintf("could not execute enrol command: %v", err))
	}

	bs, err := json.MarshalIndent(resp, "", "  ")
	if err != nil {
		panic(fmt.Sprintf("could not marshal enrol response: %v", err))
	}
	fmt.Println(string(bs))

	// Output:
	// {
	//   "action": "created",
	//   "item": {
	//     "id": "agentID",
	//     "active": true,
	//     "policy_id": "policyID",
	//     "type": "PERMANENT",
	//     "enrolled_at": "2009-11-10T23:00:00Z",
	//     "user_provided_metadata": null,
	//     "local_metadata": {
	//       "elastic": {
	//         "agent": {
	//           "build.original": "",
	//           "id": "agentID",
	//           "log_level": "",
	//           "snapshot": false,
	//           "upgradeable": false,
	//           "version": ""
	//         }
	//       },
	//       "host": null,
	//       "os": null
	//     },
	//     "actions": null,
	//     "access_api_key": "apiKeyKey",
	//     "tags": null
	//   }
	// }
	//
}

type agentInfo string

func (a agentInfo) AgentID() string {
	return string(a)
}

type sender struct {
	url, path string
}

func (s sender) Send(
	ctx context.Context,
	method string,
	path string,
	params url.Values,
	headers http.Header,
	body io.Reader) (*http.Response, error) {

	r, err := http.NewRequest(method, s.url+path, body)
	if err != nil {
		panic(fmt.Sprintf("could not create new request to fleet-test-server: %v", err))
	}
	r.Header.Set(NewAuthorizationHeader(""))

	return http.DefaultClient.Do(r)
}

func (s sender) URI() string {
	return s.url + s.path
}
