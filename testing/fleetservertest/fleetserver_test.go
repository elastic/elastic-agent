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

func ExampleNewServer_ack() {
	agentID := "agentID"
	actionID := "actionID"

	handlers := &Handlers{
		AckFn: NewHandlerAck(),
	}
	ts := NewServer(handlers, Data{})

	cmdAck := fleetapi.NewAckCmd(
		agentInfo(agentID), sender{url: ts.URL, path: NewPathAgentAcks(agentID)})

	respAck, err := cmdAck.Execute(context.Background(),
		&fleetapi.AckRequest{Events: []fleetapi.AckEvent{
			{
				EventType: "ACTION_RESULT",
				SubType:   "ACKNOWLEDGED",
				Timestamp: "2022-12-01T01:02:03.00004-07:00",
				ActionID:  actionID,
				AgentID:   agentID,
				Message: fmt.Sprintf("Action '%s' of type 'ACTION_TYPE' acknowledged.",
					actionID),
			},
			{
				EventType: "ACTION_RESULT",
				SubType:   "ACKNOWLEDGED",
				Timestamp: "2022-12-01T01:02:03.00004-07:00",
				ActionID:  "not-received-on-checkin",
				AgentID:   agentID,
				Message: fmt.Sprintf("Action '%s' of type 'unknwon_action' acknowledged.",
					"not-received-on-checkin"),
			}}})
	if err != nil {
		panic(fmt.Sprintf("failed executing checkin: %v", err))
	}
	fmt.Printf("%#v\n", respAck)

	// Output:
	// &fleetapi.AckResponse{Action:"acks", Errors:false, Items:[]fleetapi.AckResponseItem{fleetapi.AckResponseItem{Status:200, Message:"OK"}, fleetapi.AckResponseItem{Status:200, Message:"OK"}}}
}

func ExampleNewServer_enrol() {
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

func ExampleNewServer_checkin_fakeComponent() {
	agentID := "agentID"
	policyID := "policyID"
	tmpl := TmplData{
		AckToken:   "AckToken",
		AgentID:    "AgentID",
		ActionID:   "ActionID",
		PolicyID:   policyID,
		FleetHosts: `"host1", "host2"`,
		SourceURI:  "http://source.uri",
		CreatedAt:  "2023-05-31T11:37:50.607Z",
		Output: struct {
			APIKey string
			Hosts  string
			Type   string
		}{APIKey: "APIKey", Hosts: `"host1", "host2"`, Type: "Type"},
	}

	actions, err := NewActionPolicyChangeWithFakeComponent(tmpl)
	if err != nil {
		panic(fmt.Sprintf("failed to get new actions: %v", err))
	}

	var count int
	nextAction := func() (string, *HTTPError) {
		defer func() { count++ }()

		switch count {
		case 0:
			return actions, nil
		case 1:
			return "", &HTTPError{StatusCode: http.StatusTeapot}
		}

		return "[]", nil
	}

	ts := NewServer(&Handlers{
		CheckinFn: NewHandlerCheckinFakeComponent(nextAction),
	}, Data{})

	// 1st call, nextAction() will return a POLICY_CHANGE.
	cmd := fleetapi.NewCheckinCmd(
		agentInfo(agentID), sender{url: ts.URL, path: NewPathCheckin(agentID)})
	resp, _, err := cmd.Execute(context.Background(), &fleetapi.CheckinRequest{})
	if err != nil {
		panic(fmt.Sprintf("failed executing 3rd checkin: %v", err))
	}
	fmt.Println(resp.Actions)

	// 2nd subsequent call to nextAction() will return an error.
	resp, _, err = cmd.Execute(context.Background(), &fleetapi.CheckinRequest{})
	if err == nil {
		panic("expected an error, got none")
	}
	fmt.Println("Error:", err)

	// any subsequent call to nextAction() will return no action.
	resp, _, err = cmd.Execute(context.Background(), &fleetapi.CheckinRequest{})
	if err != nil {
		panic(fmt.Sprintf("failed executing 3rd checkin: %v", err))
	}
	fmt.Println(resp.Actions)

	// Output:
	// [action_id: ActionID, type: POLICY_CHANGE]
	// Error: status code: 418, fleet-server returned an error: I'm a teapot
	// []
}

func ExampleNewServer_ackWithAcker() {
	agentID := "agentID"
	actionID := "ActionID"

	// The 'acker'. It takes the actionID and returns the appropriated
	// AckResponseItem.
	// This acker returns:
	//  - success for the POLICY_CHANGE action defined above
	//  - not found for any other
	acker := func(id string) (AckResponseItem, bool) {
		if id == actionID {
			return AckResponseItem{
				Status:  http.StatusOK,
				Message: http.StatusText(http.StatusOK),
			}, false
		}

		return AckResponseItem{
			Status:  http.StatusNotFound,
			Message: fmt.Sprintf("action %s not found", id),
		}, true
	}

	handlers := &Handlers{
		AckFn: NewHandlerAckWithAcker(acker),
	}
	ts := NewServer(handlers, Data{})

	cmdAck := fleetapi.NewAckCmd(
		agentInfo(agentID), sender{url: ts.URL, path: NewPathAgentAcks(agentID)})

	respAck, err := cmdAck.Execute(context.Background(),
		&fleetapi.AckRequest{Events: []fleetapi.AckEvent{
			{
				EventType: "ACTION_RESULT",
				SubType:   "ACKNOWLEDGED",
				Timestamp: "2022-12-01T01:02:03.00004-07:00",
				ActionID:  actionID,
				AgentID:   agentID,
				Message: fmt.Sprintf("Action '%s' of type 'ACTION_TYPE' acknowledged.",
					actionID),
			},
			{
				EventType: "ACTION_RESULT",
				SubType:   "ACKNOWLEDGED",
				Timestamp: "2022-12-01T01:02:03.00004-07:00",
				ActionID:  "not-received-on-checkin",
				AgentID:   "invalid-action-id",
				Message: fmt.Sprintf("Action '%s' of type 'unknwon_action' acknowledged.",
					"not-received-on-checkin"),
			}}})
	if err != nil {
		panic(fmt.Sprintf("failed executing checkin: %v", err))
	}
	fmt.Printf("%#v\n", respAck)

	// Output:
	// &fleetapi.AckResponse{Action:"acks", Errors:true, Items:[]fleetapi.AckResponseItem{fleetapi.AckResponseItem{Status:200, Message:"OK"}, fleetapi.AckResponseItem{Status:404, Message:"action not-received-on-checkin not found"}}}
}

func ExampleNewServer_checkin_and_ackWithAcker() {
	agentID := "agentID"
	actionID := "ActionID"
	policyID := "policyID"
	ackToken := "AckToken"
	apiKey := APIKey{
		ID:  "apiKey_key",
		Key: "apiKey_id",
	}

	// =========================================================================
	// 1st - defining the check in =============================================

	// create a POLICY_CHANGE action with a valid policy and the fake-inout
	tmpl := TmplData{
		AckToken:   ackToken,
		AgentID:    agentID,
		ActionID:   actionID,
		PolicyID:   policyID,
		FleetHosts: `"host1", "host2"`,
		SourceURI:  "http://source.uri",
		CreatedAt:  "2023-05-31T11:37:50.607Z",
		Output: struct {
			APIKey string
			Hosts  string
			Type   string
		}{APIKey: apiKey.Key, Hosts: `"host1", "host2"`, Type: "Type"},
	}
	actions, err := NewActionPolicyChangeWithFakeComponent(tmpl)
	if err != nil {
		panic(fmt.Sprintf("failed to get new actions: %v", err))
	}

	// create an action generator: the mock fleet-server will call the action generator
	// each time a checkin is made to get the action to return to the agent.
	// The fleet-server keeps no knowledge about the actions returned by the generator,
	// the actions it sends to the agent.
	// This generator returns:
	//  1st - a POLICY_CHANGE action with the fake input
	//  2nd - an error http.StatusTeapot
	//  all other calls - no action
	var count int
	nextAction := func() (string, *HTTPError) {
		defer func() { count++ }()

		switch count {
		case 0:
			return actions, nil
		case 1:
			return "", &HTTPError{StatusCode: http.StatusTeapot}
		}

		return "[]", nil
	}

	// =========================================================================
	// 2nd - defining the acks. it depends on the actions returned during checkin.

	// define the 'acker'. It takes the actionID and returns the appropriated
	// AckResponseItem.
	// This acker returns:
	//  - success for the POLICY_CHANGE action defined above
	//  - not found for any other
	acker := func(id string) (AckResponseItem, bool) {
		if id == actionID {
			return AckResponseItem{
				Status:  http.StatusOK,
				Message: http.StatusText(http.StatusOK),
			}, false
		}

		return AckResponseItem{
			Status:  http.StatusNotFound,
			Message: fmt.Sprintf("action %s not found", id),
		}, true
	}

	// =========================================================================
	// 3rd - define the implementation for the fleet-server handlers we'll use
	// and create the mock fleet-server
	handlers := &Handlers{
		CheckinFn: NewHandlerCheckinFakeComponent(nextAction),
		AckFn:     NewHandlerAckWithAcker(acker),
		StatusFn:  NewHandlerStatusHealth(),
	}
	ts := NewServer(handlers, Data{})

	// =========================================================================
	// 4th - instantiate the fleetapi commands
	cmdCheckin := fleetapi.NewCheckinCmd(
		agentInfo(agentID), sender{url: ts.URL, path: NewPathCheckin(agentID)})
	cmdAck := fleetapi.NewAckCmd(
		agentInfo(agentID), sender{url: ts.URL, path: NewPathAgentAcks(agentID)})

	// =========================================================================
	// 5th - Simulate the checkin -> ack flow by calling the checkin and ack
	// commands in order

	// 1st checkin: it will return a POLICY_CHANGE.
	// TODO: make the acker only ack if the checkin was called
	respCheckin, _, err := cmdCheckin.Execute(context.Background(), &fleetapi.CheckinRequest{})
	if err != nil {
		panic(fmt.Sprintf("failed executing 3rd checkin: %v", err))
	}
	fmt.Println("[1st checkin]", respCheckin.Actions)

	// 1st ack: acking the POLICY_CHANGE
	respAck, err := cmdAck.Execute(context.Background(),
		&fleetapi.AckRequest{Events: []fleetapi.AckEvent{
			{
				EventType: "ACTION_RESULT",
				SubType:   "ACKNOWLEDGED",
				Timestamp: "2022-12-01T01:02:03.00004-07:00",
				ActionID:  actionID,
				AgentID:   agentID,
				Message: fmt.Sprintf("Action '%s' of type 'ACTION_TYPE' acknowledged.",
					actionID),
			}}})
	if err != nil {
		panic(fmt.Sprintf("failed executing checkin: %v", err))
	}
	fmt.Printf("[1st ack] %#v\n", respAck)

	// 2nd checkin: it will fail.
	respCheckin, _, err = cmdCheckin.Execute(context.Background(), &fleetapi.CheckinRequest{})
	if err == nil {
		panic("expected an error, got none")
	}
	fmt.Println("[2nd checkin] Error:", err)

	// 2nd ack: acking an action not received during checkin
	respAck, err = cmdAck.Execute(context.Background(),
		&fleetapi.AckRequest{Events: []fleetapi.AckEvent{
			{
				EventType: "ACTION_RESULT",
				SubType:   "ACKNOWLEDGED",
				Timestamp: "2022-12-01T01:02:03.00004-07:00",
				ActionID:  "not-received-on-checkin",
				AgentID:   agentID,
				Message: fmt.Sprintf("Action '%s' of type 'unknwon_action' acknowledged.",
					"not-received-on-checkin"),
			}}})
	if err != nil {
		panic(fmt.Sprintf("failed executing checkin: %v", err))
	}
	fmt.Printf("[2nd ack] %#v\n", respAck)

	// Output:
	// [1st checkin] [action_id: ActionID, type: POLICY_CHANGE]
	// [1st ack] &fleetapi.AckResponse{Action:"acks", Errors:false, Items:[]fleetapi.AckResponseItem{fleetapi.AckResponseItem{Status:200, Message:"OK"}}}
	// [2nd checkin] Error: status code: 418, fleet-server returned an error: I'm a teapot
	// [2nd ack] &fleetapi.AckResponse{Action:"acks", Errors:true, Items:[]fleetapi.AckResponseItem{fleetapi.AckResponseItem{Status:404, Message:"action not-received-on-checkin not found"}}}
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
