// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration

package ess

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/pkg/fleetapi"
	integrationtest "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/tools/check"
	"github.com/elastic/elastic-agent/pkg/testing/tools/testcontext"
	"github.com/elastic/elastic-agent/testing/fleetservertest"
	"github.com/elastic/elastic-agent/testing/integration"
)

// TestFleetRestartAction validates the end-to-end RESTART action flow for an
// agent installed with the install sub-command (tar.gz/zip): the agent receives
// a RESTART action on checkin, re-execs itself, and only acknowledges the action
// to Fleet after it has restarted.
func TestFleetRestartAction(t *testing.T) {
	_ = define.Require(t, define.Requirements{
		Group: integration.Fleet,
		Stack: &define.Stack{},
		Local: false, // requires Agent installation
		Sudo:  true,  // requires Agent installation
	})

	ctx, cancel := testcontext.WithTimeout(t, t.Context(), time.Minute*10)
	defer cancel()

	fixture, err := define.NewFixtureFromLocalBuild(t,
		define.Version(),
		integrationtest.WithAllowErrors(),
		integrationtest.WithLogOutput())
	require.NoError(t, err, "NewFixtureFromLocalBuild failed")

	runFleetRestartActionTest(ctx, t, fixture, integrationtest.InstallOpts{
		Force:          true,
		NonInteractive: true,
		Insecure:       true,
		Privileged:     false,
	})
}

// TestFleetRestartActionDeb validates the same RESTART flow as
// TestFleetRestartAction for an agent installed from a DEB package (managed by
// systemd, not installed via the install sub-command). This exercises the
// relaxed restart precondition that allows supervised-but-not-installed
// deployments to restart.
func TestFleetRestartActionDeb(t *testing.T) {
	define.Require(t, define.Requirements{
		Group: integration.Deb,
		Stack: &define.Stack{},
		Sudo:  true,
		OS: []define.OS{
			{
				Type:   define.Linux,
				Distro: "ubuntu",
			},
			{
				Type:   define.Linux,
				Distro: "debian",
			},
		},
	})

	// Package installs (apt) add real overhead on top of the serial waits below,
	// so the outer budget is larger than the tar.gz install test's.
	ctx, cancel := testcontext.WithTimeout(t, t.Context(), time.Minute*20)
	defer cancel()

	fixture, err := define.NewFixtureFromLocalBuild(t,
		define.Version(),
		integrationtest.WithPackageFormat("deb"),
		integrationtest.WithAllowErrors(),
		integrationtest.WithLogOutput())
	require.NoError(t, err, "failed to create DEB fixture")

	runFleetRestartActionTest(ctx, t, fixture, integrationtest.InstallOpts{
		Force:          true,
		NonInteractive: true,
		Insecure:       true,
		Privileged:     true,
	})
}

// TestFleetRestartActionRpm validates the same RESTART flow as
// TestFleetRestartActionDeb for an agent installed from an RPM package.
func TestFleetRestartActionRpm(t *testing.T) {
	define.Require(t, define.Requirements{
		Group: integration.RPM,
		Stack: &define.Stack{},
		Sudo:  true,
		OS: []define.OS{
			{
				Type:   define.Linux,
				Distro: "rhel",
			},
		},
	})

	// Package installs (yum) add real overhead on top of the serial waits below,
	// so the outer budget is larger than the tar.gz install test's.
	ctx, cancel := testcontext.WithTimeout(t, t.Context(), time.Minute*20)
	defer cancel()

	fixture, err := define.NewFixtureFromLocalBuild(t,
		define.Version(),
		integrationtest.WithPackageFormat("rpm"),
		integrationtest.WithAllowErrors(),
		integrationtest.WithLogOutput())
	require.NoError(t, err, "failed to create RPM fixture")

	runFleetRestartActionTest(ctx, t, fixture, integrationtest.InstallOpts{
		Force:          true,
		NonInteractive: true,
		Insecure:       true,
		Privileged:     true,
	})
}

// runFleetRestartActionTest installs and enrolls the given fixture against a
// mock Fleet Server, delivers a RESTART action, and asserts the agent
// restarts: the action is acknowledged without an error (which only happens via
// the next-startup pending-ack path, i.e. after a successful re-exec) and the
// agent reconnects to Fleet afterwards. installOpts.EnrollOpts is filled in by
// this helper with the mock server URL.
func runFleetRestartActionTest(ctx context.Context, t *testing.T, fixture *integrationtest.Fixture, installOpts integrationtest.InstallOpts) {
	t.Helper()

	apiKey, policy := createBasicFleetPolicyData(t, "http://fleet-server:8221")
	checkinWithAcker := fleetservertest.NewCheckinActionsWithAcker()
	nextActionGenerator := checkinWithAcker.ActionsGenerator()
	acker := checkinWithAcker.Acker()

	// ackErrors records, per action ID, the error reported in the agent's ack
	// (empty when none). A successful RESTART is acked without an error on the
	// next startup; a failed or expired RESTART is acked immediately WITH an
	// error. Recording it lets us require a successful restart rather than
	// treating any ack as success.
	var ackMu sync.Mutex
	ackErrors := make(map[string]string)

	handlers := &fleetservertest.Handlers{
		APIKey:          apiKey.Key,
		EnrollmentToken: "enrollmentToken",
		AgentID:         policy.AgentID, // as there is no enroll, the agentID needs to be manually set
		CheckinFn: func(ctx context.Context, h *fleetservertest.Handlers, id string, userAgent string,
			acceptEncoding string, checkinRequest fleetservertest.CheckinRequest,
		) (*fleetservertest.CheckinResponse, *fleetservertest.HTTPError) {
			if id != policy.AgentID {
				return nil, &fleetservertest.HTTPError{
					StatusCode: http.StatusNotFound,
					Message:    fmt.Sprintf("agent %q not found", id),
				}
			}

			data, hErr := nextActionGenerator()
			if hErr != nil {
				return nil, hErr
			}

			respStr := fleetservertest.NewCheckinResponse(data.AckToken, data.Actions...)
			resp := fleetservertest.CheckinResponse{}
			if err := json.Unmarshal([]byte(respStr), &resp); err != nil {
				return nil, &fleetservertest.HTTPError{
					StatusCode: http.StatusInternalServerError,
					Message:    fmt.Sprintf("failed to CheckinResponse: %v", err),
				}
			}

			// simulate long poll
			time.Sleep(data.Delay)

			return &resp, nil
		},
		EnrollFn: fleetservertest.NewHandlerEnroll(policy.AgentID, policy.PolicyID, apiKey),
		// Custom ack handler: like NewHandlerAckWithAcker, but also records the
		// per-action ack error so the test can distinguish a successful restart
		// (no error) from a failed/expired one (error present).
		AckFn: func(ctx context.Context, h *fleetservertest.Handlers, agentID string,
			ackRequest fleetservertest.AckRequest,
		) (*fleetservertest.AckResponse, *fleetservertest.HTTPError) {
			if agentID != policy.AgentID {
				return nil, &fleetservertest.HTTPError{
					StatusCode: http.StatusNotFound,
					Message:    fmt.Sprintf("agent %q not found", agentID),
				}
			}
			resp := fleetservertest.AckResponse{Action: "acks"}
			for _, e := range ackRequest.Events {
				ackMu.Lock()
				ackErrors[e.ActionId] = e.Error
				ackMu.Unlock()
				item, isErr := acker(e.ActionId)
				resp.Errors = resp.Errors || isErr
				resp.Items = append(resp.Items, item)
			}
			return &resp, nil
		},
		StatusFn: fleetservertest.NewHandlerStatusHealthy(),
	}

	fleetServer := fleetservertest.NewServer(handlers, fleetservertest.WithRequestLog(t.Logf))
	defer fleetServer.Close()

	err := fixture.EnsurePrepared(ctx)
	require.NoError(t, err, "fixture.EnsurePrepared failed")

	installOpts.EnrollOpts = integrationtest.EnrollOpts{
		URL:             fleetServer.LocalhostURL,
		EnrollmentToken: "anythingWillDO",
	}
	out, err := fixture.Install(ctx, &installOpts)
	require.NoErrorf(t, err, "Error when installing agent, output: %s", out)

	// Wait for the agent to connect to Fleet and report HEALTHY.
	require.True(t, check.ConnectedToFleet(ctx, t, fixture, 5*time.Minute),
		"agent did not connect to Fleet after install")

	// Deliver a RESTART action on the next checkin.
	restartActionID := "restart-action-id"
	restartAction, err := fleetservertest.NewAction(fleetservertest.ActionTmpl{
		AgentID:  policy.AgentID,
		ActionID: restartActionID,
		Type:     fleetapi.ActionTypeRestart,
		Data:     "{}",
	})
	require.NoError(t, err, "failed to create restart action")
	checkinWithAcker.AddCheckin("token", 1*time.Second, restartAction)

	// The RESTART action is acknowledged only after the agent has restarted: the
	// handler persists the action and re-execs, and the ack is sent on the next
	// startup via the pending-ack path. Crucially, a *successful* restart is acked
	// with no error, while a failed or expired restart is acked immediately *with*
	// an error. Requiring an error-free ack therefore proves the full persist ->
	// re-exec -> startup-ack flow actually completed (the agent re-execs in place,
	// so its PID is unchanged and cannot be used as the signal).
	require.EventuallyWithT(t, func(collect *assert.CollectT) {
		if !assert.True(collect, checkinWithAcker.Acked(restartActionID),
			"restart action has not been acknowledged to Fleet") {
			return
		}
		ackMu.Lock()
		ackErr := ackErrors[restartActionID]
		ackMu.Unlock()
		assert.Empty(collect, ackErr,
			"restart action was acknowledged with an error (the restart failed): %s", ackErr)
	}, 5*time.Minute, 500*time.Millisecond, "agent did not successfully acknowledge the restart action after restarting")

	// After re-exec the agent must reconnect to Fleet. We assert on the Fleet
	// connection state rather than the overall agent state: with this minimal
	// mock Fleet policy the agent does not necessarily reach a fully-HEALTHY
	// overall state, but it must re-establish its Fleet connection after
	// restarting.
	require.True(t, check.ConnectedToFleet(ctx, t, fixture, 5*time.Minute),
		"agent did not reconnect to Fleet after restart")
}
