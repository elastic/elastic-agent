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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/pkg/fleetapi"
	atesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/tools/check"
	"github.com/elastic/elastic-agent/pkg/testing/tools/testcontext"
	"github.com/elastic/elastic-agent/testing/fleetservertest"
	"github.com/elastic/elastic-agent/testing/integration"
)

// TestFleetRestartActionDeb validates that an agent installed from a DEB package
// (managed by systemd, not installed via the install sub-command) handles the
// Fleet RESTART action: it re-execs itself and acknowledges the action only
// after restarting. This exercises the relaxed restart precondition that allows
// supervised-but-not-installed deployments to restart.
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

	// Package installs (apt/yum) add real overhead on top of the serial waits
	// below, so the outer budget is larger than the tar.gz install test's.
	ctx, cancel := testcontext.WithTimeout(t, t.Context(), time.Minute*20)
	defer cancel()

	fixture, err := define.NewFixtureFromLocalBuild(t, define.Version(), atesting.WithPackageFormat("deb"))
	require.NoError(t, err, "failed to create DEB fixture")

	runPackageRestartActionTest(ctx, t, fixture)
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

	// Package installs (apt/yum) add real overhead on top of the serial waits
	// below, so the outer budget is larger than the tar.gz install test's.
	ctx, cancel := testcontext.WithTimeout(t, t.Context(), time.Minute*20)
	defer cancel()

	fixture, err := define.NewFixtureFromLocalBuild(t, define.Version(), atesting.WithPackageFormat("rpm"))
	require.NoError(t, err, "failed to create RPM fixture")

	runPackageRestartActionTest(ctx, t, fixture)
}

// runPackageRestartActionTest installs and enrolls the given package-based
// fixture against a mock Fleet Server, delivers a RESTART action, and asserts
// that the agent acknowledges it (proving the persist -> re-exec -> startup-ack
// flow) and reconnects to Fleet afterwards.
func runPackageRestartActionTest(ctx context.Context, t *testing.T, fixture *atesting.Fixture) {
	t.Helper()

	apiKey, policy := createBasicFleetPolicyData(t, "http://fleet-server:8221")
	checkinWithAcker := fleetservertest.NewCheckinActionsWithAcker()
	nextActionGenerator := checkinWithAcker.ActionsGenerator()

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
		AckFn:    fleetservertest.NewHandlerAckWithAcker(checkinWithAcker.Acker()),
		StatusFn: fleetservertest.NewHandlerStatusHealthy(),
	}

	fleetServer := fleetservertest.NewServer(handlers, fleetservertest.WithRequestLog(t.Logf))
	defer fleetServer.Close()

	// DEB/RPM installs register a systemd service and then enroll via the
	// elastic-agent enroll sub-command against the mock Fleet Server.
	out, err := fixture.Install(
		ctx,
		&atesting.InstallOpts{
			Force:          true,
			NonInteractive: true,
			Insecure:       true,
			Privileged:     true,
			EnrollOpts: atesting.EnrollOpts{
				URL:             fleetServer.LocalhostURL,
				EnrollmentToken: "anythingWillDO",
			},
		})
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

	// The RESTART action is acknowledged only after the agent has restarted:
	// the handler persists the action and re-execs, and the ack is sent on the
	// next startup via the pending-ack path. A successful ack therefore proves
	// the full persist -> re-exec -> startup-ack flow worked end-to-end with
	// Fleet Server for a package-managed agent. (The agent re-execs in-place, so
	// systemd keeps tracking the same PID.)
	require.EventuallyWithT(t, func(collect *assert.CollectT) {
		assert.True(collect, checkinWithAcker.Acked(restartActionID),
			"restart action has not been acknowledged to Fleet")
	}, 5*time.Minute, 500*time.Millisecond, "agent did not acknowledge the restart action after restarting")

	// After re-exec the agent must reconnect to Fleet. We assert on the Fleet
	// connection state rather than the overall agent state: with this minimal
	// mock Fleet policy the agent does not necessarily reach a fully-HEALTHY
	// overall state, but it must re-establish its Fleet connection after
	// restarting.
	require.True(t, check.ConnectedToFleet(ctx, t, fixture, 5*time.Minute),
		"agent did not reconnect to Fleet after restart")
}
