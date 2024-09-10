// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package fleetservertest

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi"
)

// TestRunFleetServer shows how to configure and run a fleet-server capable of
// enrolling and send actions to a single agent.
// For a detailed explanation of each piece and how to put them work together,
// look at ExampleNewServer_checkin_and_ackWithAcker.
// There is no authentication and the enrollment token is ignored, thus it can
// be any value.
func TestRunFleetServer(t *testing.T) {
	t.Skip("use this test if you want a mock fleet-server running to enroll a real agent")
	agentID := "agentID"
	// actionID := "ActionID"
	policyID := "policyID"
	// ackToken := "AckToken"
	enrolmentToken := "enrolmentToken" //nolint:gosec // it's a test
	apiKey := APIKey{
		ID:  "myKeyID",
		Key: "myvaKeyKey",
	}

	// FleetHosts needs to be changed after the server is running, so we can
	// get the port the server is listening on. Therefore, the action generator
	// captures the 'fleetHosts' variable, so it can read the real fleet-server
	// address from it.
	// If you want to predefine an address for the server to listen on, pass
	// WithAddress(addr) to NewServer.
	fleetHosts := []string{"host1"}
	var actionsIdx int

	tmpl := TmplPolicy{
		// AckToken: ackToken,
		AgentID: agentID,
		// ActionID: actionID,
		PolicyID: policyID,
		// FleetHosts needs to be changed after the server is running, so we can
		// get the port the server is listening on. Therefore, the action generator
		// captures the 'fleetHosts' variable, so it can read the real fleet-server
		// address from it.
		FleetHosts: []string{"host1", "host2"},
		SourceURI:  "http://source.uri",
		CreatedAt:  "2023-05-31T11:37:50.607Z",
		Output: struct {
			APIKey string
			Hosts  string
			Type   string
		}{
			APIKey: apiKey.String(),
			Hosts:  `"https://my.clould.elstc.co:443"`,
			Type:   "elasticsearch"},
	}

	nextAction := func() (CheckinAction, *HTTPError) {
		defer func() { actionsIdx++ }()
		tmpl.FleetHosts = fleetHosts

		action, err := NewActionPolicyChangeWithFakeComponent("actionID", tmpl)
		if err != nil {
			panic(fmt.Sprintf("failed to get new action: %v", err))
		}

		switch actionsIdx {
		case 0:
			return CheckinAction{
					AckToken: "tmpl.AckToken", Actions: []string{action.data}},
				nil
		}

		return CheckinAction{}, nil
	}

	acker := func(id string) (AckResponseItem, bool) {
		return AckResponseItem{
			Status:  http.StatusOK,
			Message: http.StatusText(http.StatusOK),
		}, false
	}

	ts := NewServerWithHandlers(
		apiKey,
		enrolmentToken,
		agentID,
		policyID,
		nextAction,
		acker,
		WithRequestLog(t.Logf))
	defer ts.Close()

	fleetHosts = []string{fmt.Sprintf(`"%s"`, ts.URL)}

	fmt.Println("listening on:", fleetHosts)               //nolint:forbidigo // it's a test
	fmt.Println("press CTRL + C or kill the test to stop") //nolint:forbidigo // it's a test
	wg := sync.WaitGroup{}
	wg.Add(1)
	wg.Wait()
}

func ExampleNewServer_status() {
	apiKey := "aAPIKey"
	ts := NewServer(&Handlers{
		APIKey:   apiKey,
		StatusFn: NewHandlerStatusHealthy(),
	})

	r, err := http.NewRequest(http.MethodGet, ts.URL+PathStatus, nil) //nolint:noctx // it's a test
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
	tmpl := TmplPolicy{}

	actions, err := NewActionPolicyChangeWithFakeComponent("anActionID", tmpl)
	if err != nil {
		panic(fmt.Sprintf("failed to get new actions: %v", err))
	}

	// NewHandlerCheckin
	ts := NewServer(&Handlers{
		CheckinFn: NewHandlerCheckin(func() (CheckinAction, *HTTPError) {
			return CheckinAction{Actions: []string{actions.data}}, nil
		})},
		WithAgentID(agentID))

	cmd := fleetapi.NewCheckinCmd(
		agentInfo(agentID), sender{url: ts.URL, path: NewPathCheckin(agentID)})

	got, _, err := cmd.Execute(context.Background(), &fleetapi.CheckinRequest{})
	if err != nil {
		panic(fmt.Sprintf("ExampleNewServer_checkin failed executing checkin: %v", err))
	}

	fmt.Println(got.Actions)
	// Output:
	// [id: anActionID, type: POLICY_CHANGE]
}

func ExampleNewServer_checkin_fleetConnectionParams() {
	agentID := "agentID"
	tmpl := TmplPolicy{
		FleetHosts: []string{"https://fleet.somehost.somedomain"},
		SSL: &SSL{
			Renegotiation:          "never",
			VerificationMode:       "",
			CertificateAuthorities: []string{"/path/to/CA1", "/path/to/CA2"},
			Certificate:            "/path/to/certificate",
			Key:                    "/path/to/key",
		},
	}

	actions, err := NewActionPolicyChangeWithFakeComponent("anActionID", tmpl)
	if err != nil {
		panic(fmt.Sprintf("failed to get new actions: %v", err))
	}

	// NewHandlerCheckin
	ts := NewServer(&Handlers{
		CheckinFn: NewHandlerCheckin(func() (CheckinAction, *HTTPError) {
			return CheckinAction{Actions: []string{actions.data}}, nil
		})},
		WithAgentID(agentID))

	cmd := fleetapi.NewCheckinCmd(
		agentInfo(agentID), sender{url: ts.URL, path: NewPathCheckin(agentID)})

	got, _, err := cmd.Execute(context.Background(), &fleetapi.CheckinRequest{})
	if err != nil {
		panic(fmt.Sprintf("ExampleNewServer_checkin_fleetConnectionParams failed executing checkin: %v", err))
	}

	fmt.Println(got.Actions)
	if len(got.Actions) > 0 {
		policy := got.Actions[0].(*fleetapi.ActionPolicyChange).Data.Policy
		b := new(strings.Builder)
		encoder := json.NewEncoder(b)
		encoder.SetIndent("", "  ")
		err = encoder.Encode(policy)
		if err != nil {
			panic(fmt.Sprintf("Error marshaling received policy: %v", err))
		}
		fmt.Println(b.String())
	}

	// Output:
	// [id: anActionID, type: POLICY_CHANGE]
	// {
	//   "agent": {
	//     "download": {
	//       "sourceURI": ""
	//     },
	//     "features": {},
	//     "monitoring": {
	//       "enabled": true,
	//       "logs": true,
	//       "metrics": true,
	//       "namespace": "default",
	//       "use_output": "default"
	//     },
	//     "protection": {
	//       "enabled": false,
	//       "signing_key": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEQ9BPoHUCyLyElVpfwvKeFdUt6U9wBb+QlZNf4cy5eAwK9Xh4D8fClgciPeRs3j62i6IEeGyvOs9U3+fElyUigg==",
	//       "uninstall_token_hash": "lORSaDIQq4nglUMJwWjKrwexj4IDRJA+FtoQeeqKH/I="
	//     }
	//   },
	//   "fleet": {
	//     "hosts": [
	//       "https://fleet.somehost.somedomain"
	//     ],
	//     "ssl": {
	//       "certificate": "/path/to/certificate",
	//       "certificate_authorities": [
	//         "/path/to/CA1",
	//         "/path/to/CA2"
	//       ],
	//       "key": "/path/to/key",
	//       "renegotiation": "never"
	//     }
	//   },
	//   "id": "",
	//   "inputs": [
	//     {
	//       "data_stream": {
	//         "namespace": "default"
	//       },
	//       "id": "fake-input",
	//       "meta": {
	//         "package": {
	//           "name": "fake-input",
	//           "version": "0.0.1"
	//         }
	//       },
	//       "name": "fake-input",
	//       "package_policy_id": "",
	//       "revision": 1,
	//       "streams": [],
	//       "type": "fake-input",
	//       "use_output": "default"
	//     }
	//   ],
	//   "output_permissions": {
	//     "default": {}
	//   },
	//   "outputs": {
	//     "default": {
	//       "api_key": "",
	//       "hosts": [],
	//       "type": ""
	//     }
	//   },
	//   "revision": 2,
	//   "secret_references": [],
	//   "signed": {
	//     "data": "eyJpZCI6IjI0ZTRkMDMwLWZmYTctMTFlZC1iMDQwLTlkZWJhYTVmZWNiOCIsImFnZW50Ijp7InByb3RlY3Rpb24iOnsiZW5hYmxlZCI6ZmFsc2UsInVuaW5zdGFsbF90b2tlbl9oYXNoIjoibE9SU2FESVFxNG5nbFVNSndXaktyd2V4ajRJRFJKQStGdG9RZWVxS0gvST0iLCJzaWduaW5nX2tleSI6Ik1Ga3dFd1lIS29aSXpqMENBUVlJS29aSXpqMERBUWNEUWdBRVE5QlBvSFVDeUx5RWxWcGZ3dktlRmRVdDZVOXdCYitRbFpOZjRjeTVlQXdLOVhoNEQ4ZkNsZ2NpUGVSczNqNjJpNklFZUd5dk9zOVUzK2ZFbHlVaWdnPT0ifX19",
	//     "signature": "MEUCIQCfS6wPj/AvfFA79dwKATnvyFl/ZeyA8eKOLHg1XuA9NgIgNdhjIT+G/GZFqsVoWk5jThONhpqPhfiHLE5OkTdrwT0="
	//   }
	// }

}

func ExampleNewServer_ack() {
	agentID := "agentID"
	actionID := "actionID"

	handlers := &Handlers{
		AckFn: NewHandlerAck(),
	}
	ts := NewServer(handlers)

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

func ExampleNewServer_enroll() {
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
	})

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
		panic(fmt.Sprintf("could not execute enroll command: %v", err))
	}

	bs, err := json.MarshalIndent(resp, "", "  ")
	if err != nil {
		panic(fmt.Sprintf("could not marshal enroll response: %v", err))
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
	//           "complete": false,
	//           "id": "agentID",
	//           "log_level": "",
	//           "snapshot": false,
	//           "unprivileged": false,
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
	tmpl := TmplPolicy{
		AgentID:    "AgentID",
		PolicyID:   policyID,
		FleetHosts: []string{"host1", "host2"},
		SourceURI:  "http://source.uri",
		CreatedAt:  "2023-05-31T11:37:50.607Z",
		Output: struct {
			APIKey string
			Hosts  string
			Type   string
		}{APIKey: "APIKey", Hosts: `"host1", "host2"`, Type: "Type"},
	}

	action, err := NewActionPolicyChangeWithFakeComponent("anActionID", tmpl)
	if err != nil {
		panic(fmt.Sprintf("failed to get new action: %v", err))
	}

	var count int
	nextAction := func() (CheckinAction, *HTTPError) {
		defer func() { count++ }()

		switch count {
		case 0:
			return CheckinAction{Actions: []string{action.data}}, nil
		case 1:
			return CheckinAction{}, &HTTPError{StatusCode: http.StatusTeapot}
		}

		return CheckinAction{}, nil
	}

	ts := NewServer(&Handlers{
		AgentID:   agentID, // as there is no enrol, the agentID needs to be manually set
		CheckinFn: NewHandlerCheckin(nextAction),
	})

	// 1st call, nextAction() will return a POLICY_CHANGE.
	cmd := fleetapi.NewCheckinCmd(
		agentInfo(agentID), sender{url: ts.URL, path: NewPathCheckin(agentID)})
	resp, _, err := cmd.Execute(context.Background(), &fleetapi.CheckinRequest{})
	if err != nil {
		panic(fmt.Sprintf("failed executing 3rd checkin: %v", err))
	}
	fmt.Println(resp.Actions)

	// 2nd subsequent call to nextAction() will return an error.
	_, _, err = cmd.Execute(context.Background(), &fleetapi.CheckinRequest{})
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
	// [id: anActionID, type: POLICY_CHANGE]
	// Error: status code: 418, fleet-server returned an error: I'm a teapot
	// []
}

func ExampleNewServer_checkin_withDelay() {
	agentID := "agentID"
	policyID := "policyID"
	tmpl := TmplPolicy{
		AgentID:    "AgentID",
		PolicyID:   policyID,
		FleetHosts: []string{"host1", "host2"},
		SourceURI:  "http://source.uri",
		CreatedAt:  "2023-05-31T11:37:50.607Z",
		Output: struct {
			APIKey string
			Hosts  string
			Type   string
		}{APIKey: "APIKey", Hosts: `"host1", "host2"`, Type: "Type"},
	}

	action, err := NewActionPolicyChangeWithFakeComponent("anActionID", tmpl)
	if err != nil {
		panic(fmt.Sprintf("failed to get new actions: %v", err))
	}

	delay := 250 * time.Millisecond
	var sent bool
	nextAction := func() (CheckinAction, *HTTPError) {
		if !sent {
			sent = true
			return CheckinAction{Actions: []string{action.data}, Delay: delay}, nil
		}

		return CheckinAction{}, nil
	}

	ts := NewServer(&Handlers{
		AgentID:   agentID, // as there is no enrol, the agentID needs to be manually set
		CheckinFn: NewHandlerCheckin(nextAction),
	})

	// 1st - call actions have a delay.
	cmd := fleetapi.NewCheckinCmd(
		agentInfo(agentID), sender{url: ts.URL, path: NewPathCheckin(agentID)})

	start := time.Now()
	resp, _, err := cmd.Execute(context.Background(), &fleetapi.CheckinRequest{})
	if err != nil {
		panic(fmt.Sprintf("failed executing 3rd checkin: %v", err))
	}
	elapsed := time.Since(start)
	fmt.Printf("took more than %s: %t. response: %s\n",
		delay,
		elapsed > delay,
		resp.Actions)

	// 2nd - subsequent call to nextAction() will return immediately.
	start = time.Now()
	resp, _, err = cmd.Execute(context.Background(), &fleetapi.CheckinRequest{})
	if err != nil {
		panic(fmt.Sprintf("failed executing 3rd checkin: %v", err))
	}
	elapsed = time.Since(start)
	fmt.Printf("took more than %s: %t. response: %s\n",
		delay,
		elapsed > time.Second,
		resp.Actions)

	// Output:
	// took more than 250ms: true. response: [id: anActionID, type: POLICY_CHANGE]
	// took more than 250ms: false. response: []
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
		AgentID: agentID, // as there is no enrol, the agentID needs to be manually set
		AckFn:   NewHandlerAckWithAcker(acker),
	}
	ts := NewServer(handlers)

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

// ExampleNewServer_checkin_and_ackWithAcker demonstrates how to assemble a
// fleet-server with checkin and ack handlers which cooperate, the ack handler
// only acks actions sent on checking responses.
func ExampleNewServer_checkin_and_ackWithAcker() {
	agentID := "agentID"
	actionID := "anActionID"
	policyID := "policyID"
	apiKey := APIKey{
		ID:  "apiKey_key",
		Key: "apiKey_id",
	}

	// =========================================================================
	// 1st - defining the check in =============================================

	// create a POLICY_CHANGE action with a valid policy and the fake-inout
	tmpl := TmplPolicy{
		AgentID:    agentID,
		PolicyID:   policyID,
		FleetHosts: []string{"host1", "host2"},
		SourceURI:  "http://source.uri",
		CreatedAt:  "2023-05-31T11:37:50.607Z",
		Output: struct {
			APIKey string
			Hosts  string
			Type   string
		}{APIKey: apiKey.Key, Hosts: `"host1", "host2"`, Type: "Type"},
	}
	action, err := NewActionPolicyChangeWithFakeComponent("anActionID", tmpl)
	if err != nil {
		panic(fmt.Sprintf("failed to get new action: %v", err))
	}

	// create an action generator: the mock fleet-server will call the action generator
	// each time a checkin is made to get the action to return to the agent.
	// The fleet-server keeps no knowledge about the actions returned by the generator,
	// the actions it sends to the agent.
	// This generator returns:
	//  1st - a POLICY_CHANGE action with the fake input
	//  2nd - an error http.StatusTeapot
	//  all other calls - no action
	var actionsIdx int
	nextAction := func() (CheckinAction, *HTTPError) {
		defer func() { actionsIdx++ }()

		switch actionsIdx {
		case 0:
			return CheckinAction{Actions: []string{action.data}}, nil
		case 1:
			return CheckinAction{}, &HTTPError{StatusCode: http.StatusTeapot}
		}

		return CheckinAction{}, nil
	}

	// =========================================================================
	// 2nd - defining the acks. it depends on the actions returned during checkin.

	// define the 'acker'. It takes the actionID and returns the appropriated
	// AckResponseItem.
	// This acker returns:
	//  - success for the POLICY_CHANGE action defined above
	//  - not found for any other
	acker := func(id string) (AckResponseItem, bool) {
		// only ack the action if it was already sent in the checkin response.
		if id == actionID && actionsIdx > 0 {
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
		CheckinFn: NewHandlerCheckin(nextAction),
		AckFn:     NewHandlerAckWithAcker(acker),
		StatusFn:  NewHandlerStatusHealthy(),
	}
	ts := NewServer(handlers, WithAgentID(agentID)) // as there is no enrol, the agentID needs to be manually set

	// =========================================================================
	// 4th - instantiate the fleetapi commands
	cmdCheckin := fleetapi.NewCheckinCmd(
		agentInfo(agentID), sender{url: ts.URL, path: NewPathCheckin(agentID)})
	cmdAck := fleetapi.NewAckCmd(
		agentInfo(agentID), sender{url: ts.URL, path: NewPathAgentAcks(agentID)})

	// =========================================================================
	// 5th - Simulate the checkin -> ack flow by calling the checkin and ack
	// commands in order

	ackEventPolicyChange := fleetapi.AckEvent{
		EventType: "ACTION_RESULT",
		SubType:   "ACKNOWLEDGED",
		Timestamp: "2022-12-01T01:02:03.00004-07:00",
		ActionID:  actionID,
		AgentID:   agentID,
		Message: fmt.Sprintf("Action '%s' of type 'ACTION_TYPE' acknowledged.",
			actionID),
	}

	// 1st ack: acking an action that haven't been sent
	respAck, err := cmdAck.Execute(context.Background(),
		&fleetapi.AckRequest{Events: []fleetapi.AckEvent{ackEventPolicyChange}})
	if err != nil {
		panic(fmt.Sprintf("failed executing checkin: %v", err))
	}
	fmt.Printf("[1st ack] %#v\n", respAck)

	// 1st checkin: it will return a POLICY_CHANGE.
	// TODO: make the acker only ack if the checkin was called
	respCheckin, _, err := cmdCheckin.Execute(context.Background(), &fleetapi.CheckinRequest{})
	if err != nil {
		panic(fmt.Sprintf("failed executing 3rd checkin: %v", err))
	}
	fmt.Println("[1st checkin]", respCheckin.Actions)

	// 2dn ack: acking the POLICY_CHANGE
	respAck, err = cmdAck.Execute(context.Background(),
		&fleetapi.AckRequest{Events: []fleetapi.AckEvent{ackEventPolicyChange}})
	if err != nil {
		panic(fmt.Sprintf("failed executing checkin: %v", err))
	}
	fmt.Printf("[2nd ack] %#v\n", respAck)

	// 2nd checkin: it will fail.
	_, _, err = cmdCheckin.Execute(context.Background(), &fleetapi.CheckinRequest{})
	if err == nil {
		panic("expected an error, got none")
	}
	fmt.Println("[2nd checkin] Error:", err)

	// 3rd ack: acking an action not received during checkin
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
	fmt.Printf("[3rd ack] %#v\n", respAck)

	// Output:
	// [1st ack] &fleetapi.AckResponse{Action:"acks", Errors:true, Items:[]fleetapi.AckResponseItem{fleetapi.AckResponseItem{Status:404, Message:"action anActionID not found"}}}
	// [1st checkin] [id: anActionID, type: POLICY_CHANGE]
	// [2nd ack] &fleetapi.AckResponse{Action:"acks", Errors:false, Items:[]fleetapi.AckResponseItem{fleetapi.AckResponseItem{Status:200, Message:"OK"}}}
	// [2nd checkin] Error: status code: 418, fleet-server returned an error: I'm a teapot
	// [3rd ack] &fleetapi.AckResponse{Action:"acks", Errors:true, Items:[]fleetapi.AckResponseItem{fleetapi.AckResponseItem{Status:404, Message:"action not-received-on-checkin not found"}}}
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

	r, err := http.NewRequest(method, s.url+path, body) //nolint:noctx // it's a test
	if err != nil {
		panic(fmt.Sprintf("could not create new request to fleet-test-server: %v", err))
	}
	r.Header.Set(NewAuthorizationHeader(""))

	return http.DefaultClient.Do(r)
}

func (s sender) URI() string {
	return s.url + s.path
}
