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
	"strings"

	"github.com/elastic/elastic-agent/internal/pkg/fleetapi"
)

func ExampleNewServer_status() {
	ts := NewServer(API{
		StatusFn: NewStatusHandlerHealth(),
	})

	resp, err := http.Get(ts.URL + PathStatus) //nolint:noctx // it's fine on a test
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
		CheckinFn: NewCheckinHandler(agentID, "", false),
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
	return ""
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
	return &http.Response{
		Status:     http.StatusText(http.StatusOK),
		StatusCode: http.StatusOK,
		Body: io.NopCloser(strings.NewReader(
			checkinResponseJSONPolicySystemIntegration)),
	}, nil
}

func (s sender) URI() string {
	return s.url + s.path
}
