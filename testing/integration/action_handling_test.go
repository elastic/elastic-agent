// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	integrationtest "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/tools/check"
	"github.com/elastic/elastic-agent/testing/fleetservertest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestActionHandling(t *testing.T) {
	define.Require(t, define.Requirements{
		Group: Fleet,
		Local: false,
		Sudo:  true,
	})

	t.Run("agent restarts before all the actions in a checkin are processed", func(t *testing.T) {
		testFunc(t)
	})
}

func testFunc(t *testing.T) {
	ctx := t.Context()

	apiKey, policy := createBasicFleetPolicyData(t, "http://fleet-server:8220")
	t.Logf("Created policy data - AgentID: %s, PolicyID: %s", policy.AgentID, policy.PolicyID)

	checkinWithAcker := fleetservertest.NewCheckinActionsWithAcker()
	var checkinCounter atomic.Int32

	waitChan := make(chan struct{})
	finalWaitChan := make(chan struct{})
	ackTokenChan := make(chan string)
	checkinHandlerProvider := func(next fleetservertest.ActionsGenerator) func(
		ctx context.Context,
		h *fleetservertest.Handlers,
		agentID string,
		userAgent string,
		acceptEncoding string,
		checkinRequest fleetservertest.CheckinRequest) (*fleetservertest.CheckinResponse, *fleetservertest.HTTPError) {
		return func(
			ctx context.Context,
			h *fleetservertest.Handlers,
			agentID string,
			userAgent string,
			acceptEncoding string,
			checkinRequest fleetservertest.CheckinRequest,
		) (*fleetservertest.CheckinResponse, *fleetservertest.HTTPError) {
			defer checkinCounter.Add(1)

			t.Logf("Count: %d, CheckinRequest: Status=%s, Message=%s, AckToken='%s'", checkinCounter.Load(), checkinRequest.Status, checkinRequest.Message, checkinRequest.AckToken)

			if int(checkinCounter.Load()) == 2 {
				// Send the acktoken to the test
				<-waitChan
				ackTokenChan <- checkinRequest.AckToken
				<-finalWaitChan
			}

			data, hErr := next()
			if hErr != nil {
				t.Logf("Error from next(): %v", hErr)
				return nil, hErr
			}

			respStr := fleetservertest.NewCheckinResponse(data.AckToken, data.Actions...)

			resp := fleetservertest.CheckinResponse{}
			err := json.Unmarshal(
				[]byte(respStr),
				&resp)
			if err != nil {
				t.Logf("Failed to unmarshal response: %v", err)
				return nil, &fleetservertest.HTTPError{
					StatusCode: http.StatusInternalServerError,
					Message:    fmt.Sprintf("failed to CheckinResponse: %v", err),
				}
			}
			time.Sleep(data.Delay)

			t.Logf("Returning response with %d actions", len(resp.Actions))
			return &resp, nil
		}
	}

	waitAckChan := make(chan struct{})

	ackHandlerProvider := func(acker fleetservertest.Acker) func(
		ctx context.Context,
		h *fleetservertest.Handlers,
		agentID string,
		ackRequest fleetservertest.AckRequest) (*fleetservertest.AckResponse, *fleetservertest.HTTPError) {
		return func(
			ctx context.Context,
			h *fleetservertest.Handlers,
			agentID string,
			ackRequest fleetservertest.AckRequest,
		) (*fleetservertest.AckResponse, *fleetservertest.HTTPError) {
			if agentID != h.AgentID {
				return nil, &fleetservertest.HTTPError{
					StatusCode: http.StatusNotFound,
					Message: fmt.Sprintf("agent %q not found, expecting %q",
						agentID, h.AgentID),
				}
			}

			resp := fleetservertest.AckResponse{Action: "acks"}
			for _, e := range ackRequest.Events {
				t.Logf("ACTION ID: %s", e.ActionId)
				if e.ActionId == "test-action-id-1" {
					close(waitAckChan)
					t.Log("Acker waiting for waitChan")

					<-waitChan
					// t.Log("Acker returning from acker")
					// return &resp, nil
				}
				t.Logf("Acking action event with id: %s", e.ActionId)
				r, isErr := acker(e.ActionId)
				resp.Errors = resp.Errors || isErr
				resp.Items = append(resp.Items, r)
			}

			return &resp, nil
		}
	}

	t.Log("Creating handlers...")
	handlers := fleetservertest.Handlers{
		CheckinFn: checkinHandlerProvider(checkinWithAcker.ActionsGenerator()),
		AckFn:     ackHandlerProvider(checkinWithAcker.Acker()),
		EnrollFn:  fleetservertest.NewHandlerEnroll(policy.AgentID, policy.PolicyID, apiKey),
	}

	server := fleetservertest.NewServer(&handlers)
	defer server.Close()

	// policyChangeAction, err := fleetservertest.NewActionPolicyChangeWithFakeComponent("test-policy-change", fleetservertest.TmplPolicy{
	// 	AgentID:    policy.AgentID,
	// 	PolicyID:   policy.PolicyID,
	// 	FleetHosts: []string{server.LocalhostURL},
	// })
	// require.NoError(t, err)

	policyReassignAction, err := fleetservertest.NewAction(fleetservertest.ActionTmpl{
		AgentID:  policy.AgentID,
		ActionID: "test-action-id-0",
		Type:     "POLICY_REASSIGN",
		Data:     `{"policy_id": "new-policy-456"}`,
	})
	require.NoError(t, err)
	policyReassignAction1, err := fleetservertest.NewAction(fleetservertest.ActionTmpl{
		AgentID:  policy.AgentID,
		ActionID: "test-action-id-1",
		Type:     "POLICY_REASSIGN",
		Data:     `{"policy_id": "new-policy-456"}`,
	})
	require.NoError(t, err)
	policyReassignAction2, err := fleetservertest.NewAction(fleetservertest.ActionTmpl{
		AgentID:  policy.AgentID,
		ActionID: "test-action-id-2",
		Type:     "POLICY_REASSIGN",
		Data:     `{"policy_id": "new-policy-456"}`,
	})
	require.NoError(t, err)

	// checkinWithAcker.AddCheckin("AckToken-0", 0, policyChangeAction, policyReassignAction)
	checkinWithAcker.AddCheckin("AckToken-0", 0, policyReassignAction)
	checkinWithAcker.AddCheckin("AckToken-1", 0, policyReassignAction1, policyReassignAction2)

	fixture, err := define.NewFixtureFromLocalBuild(t, define.Version(), integrationtest.WithLogOutput())
	require.NoError(t, err)

	err = fixture.EnsurePrepared(ctx)
	require.NoError(t, err)

	out, err := fixture.Install(
		ctx,
		&integrationtest.InstallOpts{
			Force:          true,
			NonInteractive: true,
			Insecure:       true,
			Privileged:     true,
			EnrollOpts: integrationtest.EnrollOpts{
				URL:             server.LocalhostURL,
				EnrollmentToken: "anythingWillDO",
			},
		})
	require.NoErrorf(t, err, "Error when installing agent, output: %s", out)

	t.Log("Checking connection to Fleet...")
	check.ConnectedToFleet(ctx, t, fixture, 5*time.Minute)

	t.Log("Restarting agent")
	client := fixture.Client()
	client.Connect(ctx)

	<-waitAckChan

	err = client.Restart(ctx)
	assert.NoError(t, err)
	t.Log("Agent restarted")

	close(waitChan)

	ackToken := <-ackTokenChan
	t.Logf("policyReassignAction1: %s", policyReassignAction1.ActionID)
	pra1Acked := checkinWithAcker.Acked(policyReassignAction1.ActionID)
	assert.True(t, pra1Acked)

	t.Logf("policyReassignAction2: %s", policyReassignAction2.ActionID)
	pra2Acked := checkinWithAcker.Acked(policyReassignAction2.ActionID)
	assert.False(t, pra2Acked)

	t.Logf("Asserting AckToken: %s", ackToken)
	assert.Equal(t, "AckToken-0", ackToken)

	close(finalWaitChan)

	status, err := fixture.Client().State(ctx)
	require.NoError(t, err)
	t.Logf("Agent State: %s, Fleet State: %s", status.State, status.FleetState)
}
