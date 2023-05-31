package fleetserver

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/elastic/elastic-agent/internal/pkg/fleetapi"
)

func ExampleNewTest_status() {
	ts := NewTest(API{
		StatusFn: func(ctx context.Context) (*StatusResponse, *HTTPError) {
			return &StatusResponse{
				Name:   "fleet-server-test-api",
				Status: "it works!",
				Version: StatusResponseVersion{
					Number:    "1",
					BuildHash: "aHash",
					BuildTime: "now",
				},
			}, nil
		},
	})

	resp, err := http.Get(ts.URL + "/api/status")
	if err != nil {
		panic(fmt.Sprintf("could not make request to fleet-test-server: %v", err))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		if err != nil {
			panic(fmt.Sprintf("could not read response: %v", err))
		}
	}
	fmt.Printf("%s", body)

	// Output:
	// {"name":"fleet-server-test-api","status":"it works!","version":{"number":"1","build_hash":"aHash","build_time":"now"}}
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

func ExampleNewTest_checkin() {
	t := &testing.T{}
	agentID := "agentID"

	ts := NewTest(API{
		CheckinFn: func(
			ctx context.Context,
			id string,
			userAgent string,
			acceptEncoding string,
			checkinRequest CheckinRequest) (*CheckinResponse, *HTTPError) {

			resp := NewCheckinResponsePolicySystemIntegration(t,
				agentID,
				"ackToken")

			return &resp, nil
		},
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
