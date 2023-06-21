// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package fleetservertest

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/elastic/elastic-agent/internal/pkg/fleetapi"
)

func ExampleNewServer_status() {
	apiKey := "aAPIKey"
	ts := NewServer(API{
		APIKey:   apiKey,
		StatusFn: NewHandlerStatusHealth(),
	})

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

	ts := NewServer(API{
		CheckinFn: NewHandlerCheckin(agentID, "", false),
	})

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
