// Licensed to Elasticsearch B.V. under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Elasticsearch B.V. licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package fleet

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/elastic/elastic-agent/internal/pkg/core/logger"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi"
)

func TestAcker_AckCommit(t *testing.T) {
	type ackRequest struct {
		Events []fleetapi.AckEvent `json:"events"`
	}

	log, _ := logger.New("fleet_acker", false)
	client := newTestingClient()
	agentInfo := &testAgentInfo{}
	acker, err := NewAcker(log, agentInfo, client)
	if err != nil {
		t.Fatal(err)
	}

	if acker == nil {
		t.Fatal("acker not initialized")
	}

	testID := "ack-test-action-id"
	testAction := &fleetapi.ActionUnknown{ActionID: testID}

	ch := client.Answer(func(headers http.Header, body io.Reader) (*http.Response, error) {
		content, err := ioutil.ReadAll(body)
		assert.NoError(t, err)
		cr := &ackRequest{}
		err = json.Unmarshal(content, &cr)
		assert.NoError(t, err)

		assert.EqualValues(t, 1, len(cr.Events))
		assert.EqualValues(t, testID, cr.Events[0].ActionID)

		resp := wrapStrToResp(http.StatusOK, `{ "actions": [] }`)
		return resp, nil
	})

	go func() {
		for range ch {
		}
	}()

	if err := acker.Ack(context.Background(), testAction); err != nil {
		t.Fatal(err)
	}
	if err := acker.Commit(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestAcker_AckBatch(t *testing.T) {
	type ackRequest struct {
		Events []fleetapi.AckEvent `json:"events"`
	}

	log, _ := logger.New("fleet_acker", false)
	client := newTestingClient()
	agentInfo := &testAgentInfo{}
	acker, err := NewAcker(log, agentInfo, client)
	if err != nil {
		t.Fatal(err)
	}

	if acker == nil {
		t.Fatal("acker not initialized")
	}

	testID1 := "ack-test-action-id-1"
	testAction1 := &fleetapi.ActionUnknown{ActionID: testID1}
	testID2 := "ack-test-action-id-2"
	testAction2 := &fleetapi.ActionUnknown{ActionID: testID2}

	ch := client.Answer(func(headers http.Header, body io.Reader) (*http.Response, error) {
		content, err := ioutil.ReadAll(body)
		assert.NoError(t, err)
		cr := &ackRequest{}
		err = json.Unmarshal(content, &cr)
		assert.NoError(t, err)

		assert.EqualValues(t, 2, len(cr.Events))
		assert.EqualValues(t, testID1, cr.Events[0].ActionID)
		assert.EqualValues(t, testID2, cr.Events[1].ActionID)

		resp := wrapStrToResp(http.StatusOK, `{ "actions": [] }`)
		return resp, nil
	})

	go func() {
		for range ch {
		}
	}()

	if err := acker.AckBatch(context.Background(), []fleetapi.Action{testAction1, testAction2}); err != nil {
		t.Fatal(err)
	}
	if err := acker.Commit(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestAcker_AckBatch_Empty(t *testing.T) {
	log, _ := logger.New("fleet_acker", false)
	client := newNotCalledClient()
	agentInfo := &testAgentInfo{}
	acker, err := NewAcker(log, agentInfo, client)
	if err != nil {
		t.Fatal(err)
	}

	if acker == nil {
		t.Fatal("acker not initialized")
	}

	if err := acker.AckBatch(context.Background(), []fleetapi.Action{}); err != nil {
		t.Fatal(err)
	}
	if err := acker.Commit(context.Background()); err != nil {
		t.Fatal(err)
	}
	if client.called {
		t.Fatal("client should not have been used")
	}
}

type clientCallbackFunc func(headers http.Header, body io.Reader) (*http.Response, error)

type testingClient struct {
	sync.Mutex
	callback clientCallbackFunc
	received chan struct{}
}

func (t *testingClient) Send(
	_ context.Context,
	method string,
	path string,
	params url.Values,
	headers http.Header,
	body io.Reader,
) (*http.Response, error) {
	t.Lock()
	defer t.Unlock()
	defer func() { t.received <- struct{}{} }()
	return t.callback(headers, body)
}

func (t *testingClient) URI() string {
	return "http://localhost"
}

func (t *testingClient) Answer(fn clientCallbackFunc) <-chan struct{} {
	t.Lock()
	defer t.Unlock()
	t.callback = fn
	return t.received
}

func newTestingClient() *testingClient {
	return &testingClient{received: make(chan struct{}, 1)}
}

type testAgentInfo struct{}

func (testAgentInfo) AgentID() string { return "agent-secret" }

func wrapStrToResp(code int, body string) *http.Response {
	return &http.Response{
		Status:        fmt.Sprintf("%d %s", code, http.StatusText(code)),
		StatusCode:    code,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Body:          ioutil.NopCloser(bytes.NewBufferString(body)),
		ContentLength: int64(len(body)),
		Header:        make(http.Header),
	}
}

type notCalledClient struct {
	sync.Mutex
	called bool
}

func (t *notCalledClient) Send(
	_ context.Context,
	method string,
	path string,
	params url.Values,
	headers http.Header,
	body io.Reader,
) (*http.Response, error) {
	t.Lock()
	defer t.Unlock()
	t.called = true
	return nil, fmt.Errorf("should not have been called")
}

func (t *notCalledClient) URI() string {
	return "http://localhost"
}

func newNotCalledClient() *notCalledClient {
	return &notCalledClient{}
}
