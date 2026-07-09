// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package fleet

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	api "github.com/elastic/fleet-server/pkg/api"

	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/pkg/core/logger"
	"github.com/elastic/elastic-agent/pkg/fleetapi"
)

type ackRequest struct {
	Events []api.AckRequest_Events_Item `json:"events"`
}

type testAgentInfo struct{}

func (testAgentInfo) AgentID() string { return "agent-secret" }

type testSender struct {
	req *ackRequest
}

func (s *testSender) Send(
	_ context.Context,
	method string,
	path string,
	params url.Values,
	headers http.Header,
	body io.ReadSeeker,
) (*http.Response, error) {
	d := json.NewDecoder(body)
	var req ackRequest
	err := d.Decode(&req)
	if err != nil {
		return nil, err
	}
	s.req = &req
	return wrapStrToResp(http.StatusOK, `{ "action": "acks" }`), nil
}

func (s *testSender) URI() string {
	return "http://localhost"
}

func wrapStrToResp(code int, body string) *http.Response {
	return &http.Response{
		Status:        fmt.Sprintf("%d %s", code, http.StatusText(code)),
		StatusCode:    code,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Body:          io.NopCloser(bytes.NewBufferString(body)),
		ContentLength: int64(len(body)),
		Header:        make(http.Header),
	}
}

func TestAcker_Ack(t *testing.T) {
	tests := []struct {
		name    string
		actions []fleetapi.Action
		batch   bool
	}{
		{
			name:    "nil",
			actions: nil,
		},
		{
			name:    "empty",
			actions: []fleetapi.Action{},
		},
		{
			name:    "ack",
			actions: []fleetapi.Action{&fleetapi.ActionUnknown{ActionID: "ack-test-action-id", ActionType: fleetapi.ActionTypeUnknown}},
		},
		{
			name: "ackbatch",
			actions: []fleetapi.Action{
				&fleetapi.ActionUnknown{ActionID: "ack-test-action-id1", ActionType: fleetapi.ActionTypeUnknown},
				&fleetapi.ActionUnknown{ActionID: "ack-test-action-id2", ActionType: fleetapi.ActionTypeUnknown},
			},
		},
		{
			name: "ackaction",
			actions: []fleetapi.Action{
				&fleetapi.ActionApp{
					ActionID:    "1b12dcd8-bde0-4045-92dc-c4b27668d733",
					InputType:   "osquery",
					Data:        []byte(`{"query":"select * from osquery_info"}`),
					Response:    map[string]interface{}{"osquery": map[string]interface{}{"count": float64(1)}},
					StartedAt:   "2022-02-23T18:26:08.506128Z",
					CompletedAt: "2022-02-23T18:26:08.507593Z",
				},
				&fleetapi.ActionApp{
					ActionID:    "2b12dcd8-bde0-4045-92dc-c4b27668d733",
					InputType:   "osquery",
					Data:        []byte(`{"query":"select * from foobar"}`),
					StartedAt:   "2022-02-24T18:26:08.506128Z",
					CompletedAt: "2022-02-24T18:26:08.507593Z",
					Error:       "uknown table",
				},
			},
		},
		{
			name: "ackupgrade",
			actions: []fleetapi.Action{
				&fleetapi.ActionUpgrade{
					ActionID:   "upgrade-ok",
					ActionType: fleetapi.ActionTypeUpgrade,
				},
				&fleetapi.ActionUpgrade{
					ActionID:   "upgrade-retry",
					ActionType: fleetapi.ActionTypeUpgrade,
					Data: fleetapi.ActionUpgradeData{
						Retry: 1,
					},
					Err: errors.New("upgrade failed"),
				},
				&fleetapi.ActionUpgrade{
					ActionID:   "upgrade-failed",
					ActionType: fleetapi.ActionTypeUpgrade,
					Data: fleetapi.ActionUpgradeData{
						Retry: -1,
					},
					Err: errors.New("upgrade failed"),
				},
			},
		},
	}

	log, _ := logger.New("fleet_acker", false)
	agentInfo := &testAgentInfo{}

	checkRequest := func(t *testing.T, actions []fleetapi.Action, req *ackRequest) {
		if len(actions) == 0 { // If no actions, expect no request, the sender was not called
			assert.Nil(t, req)
			return
		}
		assert.EqualValues(t, len(actions), len(req.Events))
		for i, ac := range actions {
			switch a := ac.(type) {
			case *fleetapi.ActionUpgrade:
				event, err := req.Events[i].AsUpgradeEvent()
				require.NoError(t, err)
				assert.Equal(t, api.ACTIONRESULT, event.Type)
				assert.Equal(t, api.EventSubtypeACKNOWLEDGED, event.Subtype)
				assert.Equal(t, a.ID(), event.ActionId)
				assert.Equal(t, agentInfo.AgentID(), event.AgentId)
				assert.Equal(t, fmt.Sprintf("Action %q of type %q acknowledged.", a.ID(), a.Type()), event.Message)
				if a.Err != nil {
					require.NotNil(t, event.Error)
					assert.Equal(t, a.Err.Error(), *event.Error)
					// Check payload
					require.NotNil(t, event.Payload)
					assert.Equal(t, a.Data.Retry, event.Payload.RetryAttempt,
						"action ID %s failed", a.ActionID)
					// Check retry flag
					if event.Payload.RetryAttempt > 0 {
						assert.True(t, event.Payload.Retry)
					} else {
						assert.False(t, event.Payload.Retry)
					}
				} else {
					assert.Nil(t, event.Error)
				}
			case *fleetapi.ActionApp:
				event, err := req.Events[i].AsInputEvent()
				require.NoError(t, err)
				assert.Equal(t, api.ACTIONRESULT, event.Type)
				assert.Equal(t, api.EventSubtypeACKNOWLEDGED, event.Subtype)
				assert.Equal(t, a.ID(), event.ActionId)
				assert.Equal(t, agentInfo.AgentID(), event.AgentId)
				assert.Equal(t, a.InputType, event.ActionInputType)
				assert.EqualValues(t, a.Data, event.ActionData)
				wantResponse, err := json.Marshal(a.Response)
				require.NoError(t, err)
				assert.JSONEq(t, string(wantResponse), string(event.ActionResponse))
				wantStarted, err := time.Parse(time.RFC3339Nano, a.StartedAt)
				require.NoError(t, err)
				assert.True(t, wantStarted.Equal(event.StartedAt))
				wantCompleted, err := time.Parse(time.RFC3339Nano, a.CompletedAt)
				require.NoError(t, err)
				assert.True(t, wantCompleted.Equal(event.CompletedAt))
				if a.Error != "" {
					require.NotNil(t, event.Error)
					assert.Equal(t, a.Error, *event.Error)
				} else {
					assert.Nil(t, event.Error)
				}
			default:
				event, err := req.Events[i].AsGenericEvent()
				require.NoError(t, err)
				assert.Equal(t, api.ACTIONRESULT, event.Type)
				assert.Equal(t, api.EventSubtypeACKNOWLEDGED, event.Subtype)
				assert.Equal(t, ac.ID(), event.ActionId)
				assert.Equal(t, agentInfo.AgentID(), event.AgentId)
				assert.Equal(t, fmt.Sprintf("Action %q of type %q acknowledged.", ac.ID(), ac.Type()), event.Message)
			}
		}
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sender := &testSender{}
			acker, err := NewAcker(log, agentInfo, sender)
			require.NoError(t, err)
			require.NotNil(t, acker, "acker not initialized")

			if len(tc.actions) == 1 {
				err = acker.Ack(context.Background(), tc.actions[0])
			} else {
				_, err = acker.AckBatch(context.Background(), tc.actions)
			}
			require.NoError(t, err)

			err = acker.Commit(context.Background())
			require.NoError(t, err)

			checkRequest(t, tc.actions, sender.req)
		})
	}
}
