// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package workflowrunner

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/elastic/elastic-agent-client/v7/pkg/client/mock"
	"github.com/elastic/elastic-agent-client/v7/pkg/proto"
)

// TestManagerOverControlProtocol drives the runner the way the agent does: it
// sends an elasticsearch output unit and a workflow/http input unit over the V2
// control protocol, waits for the input to report healthy, then performs the
// action exactly as the agent's AppAction handler would.
func TestManagerOverControlProtocol(t *testing.T) {
	es := newFakeES(t, http.StatusCreated)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != secretToken {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte("built"))
	}))
	defer target.Close()

	outputSource, err := structpb.NewStruct(map[string]interface{}{
		"type":  "elasticsearch",
		"hosts": []interface{}{es.URL},
	})
	require.NoError(t, err)
	inputSource, err := structpb.NewStruct(map[string]interface{}{"type": ActionName})
	require.NoError(t, err)

	const inputID, outputID = "workflow-http-default", "workflow-http-default-out"
	expected := &proto.CheckinExpected{Units: []*proto.UnitExpected{
		{
			Id:             outputID,
			Type:           proto.UnitType_OUTPUT,
			State:          proto.State_HEALTHY,
			LogLevel:       proto.UnitLogLevel_INFO,
			ConfigStateIdx: 1,
			Config:         &proto.UnitExpectedConfig{Id: outputID, Type: "elasticsearch", Source: outputSource},
		},
		{
			Id:             inputID,
			Type:           proto.UnitType_INPUT,
			State:          proto.State_HEALTHY,
			LogLevel:       proto.UnitLogLevel_INFO,
			ConfigStateIdx: 1,
			Config: &proto.UnitExpectedConfig{
				Id:         inputID,
				Type:       ActionName,
				Source:     inputSource,
				DataStream: &proto.DataStream{Namespace: "team-a"},
			},
		},
	}}

	token := mock.NewID()
	var stateMu sync.Mutex
	inputState := proto.State_STARTING
	srv := mock.StubServerV2{
		CheckinV2Impl: func(observed *proto.CheckinObserved) *proto.CheckinExpected {
			if observed.Token != token {
				return nil
			}
			stateMu.Lock()
			for _, u := range observed.Units {
				if u.Id == inputID && u.Type == proto.UnitType_INPUT {
					inputState = u.State
				}
			}
			stateMu.Unlock()
			return expected
		},
		ActionImpl:  func(*proto.ActionResponse) error { return nil },
		ActionsChan: make(chan *mock.PerformAction, 10),
		SentActions: make(map[string]*mock.PerformAction),
	}
	require.NoError(t, srv.Start())
	defer srv.Stop()

	ctx := t.Context()
	c := client.NewV2(srv.GetTarget(), token, client.VersionInfo{Name: "workflow-runner"},
		client.WithGRPCDialOptions(grpc.WithTransportCredentials(insecure.NewCredentials())))
	store, err := OpenStore(t.TempDir())
	require.NoError(t, err)
	m := NewManager(zerolog.Nop(), NewExecutor(), store)

	require.NoError(t, c.Start(ctx))
	defer c.Stop()
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case change := <-c.UnitChanges():
				m.HandleChange(change)
			case <-c.Errors():
			}
		}
	}()

	require.Eventually(t, func() bool {
		stateMu.Lock()
		defer stateMu.Unlock()
		return inputState == proto.State_HEALTHY
	}, 10*time.Second, 50*time.Millisecond, "input unit never reported healthy")

	params := actionParams("action-proto", http.MethodPost, target.URL+"/job/build",
		map[string]string{"Authorization": secretToken}, "")
	ack, err := srv.PerformAction(inputID, proto.UnitType_INPUT, ActionName, params)
	require.NoError(t, err)

	assert.InDelta(t, http.StatusOK, ack["status_code"], 0, "ack: %v", ack)
	assert.Equal(t, "action-proto", ack["result_id"])
	assert.Equal(t, "logs-workflow_runner.http-team-a", ack["result_index"])
	assert.NotContains(t, ack, "error")

	reqs := es.requests()
	require.Len(t, reqs, 1)
	assert.Equal(t, "/logs-workflow_runner.http-team-a/_doc/action-proto", reqs[0].path)
	body := reqs[0].body["http"].(map[string]interface{})["response"].(map[string]interface{})["body"].(map[string]interface{})
	assert.Equal(t, "built", body["content"])
}
