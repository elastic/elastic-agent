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
	integrationtest "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/tools/check"
	"github.com/elastic/elastic-agent/pkg/testing/tools/testcontext"
	"github.com/elastic/elastic-agent/testing/fleetservertest"
	"github.com/elastic/elastic-agent/testing/integration"
)

// TestFleetUninstallAction validates the end-to-end UNINSTALL action flow against
// a Fleet Server: the agent receives an UNINSTALL action on checkin, spawns a
// detached uninstaller, and the action is acknowledged to Fleet by that
// uninstaller at the point of no return (after the agent is effectively
// uninstalled but before its credentials are removed).
func TestFleetUninstallAction(t *testing.T) {
	_ = define.Require(t, define.Requirements{
		Group: integration.Fleet,
		Stack: &define.Stack{},
		Local: false, // requires Agent installation
		Sudo:  true,  // requires Agent installation
	})

	ctx, cancel := testcontext.WithTimeout(t, t.Context(), time.Minute*10)
	defer cancel()

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

	fixture, err := define.NewFixtureFromLocalBuild(t,
		define.Version(),
		integrationtest.WithAllowErrors(),
		integrationtest.WithLogOutput())
	require.NoError(t, err, "SetupTest: NewFixtureFromLocalBuild failed")
	err = fixture.EnsurePrepared(ctx)
	require.NoError(t, err, "SetupTest: fixture.Prepare failed")

	out, err := fixture.Install(
		ctx,
		&integrationtest.InstallOpts{
			Force:          true,
			NonInteractive: true,
			Insecure:       true,
			// The UNINSTALL action requires root/administrator privileges (an
			// unprivileged agent's service runs as a non-root user and cannot
			// remove its own service), so install privileged here.
			Privileged: true,
			EnrollOpts: integrationtest.EnrollOpts{
				URL:             fleetServer.LocalhostURL,
				EnrollmentToken: "anythingWillDO",
			}})
	require.NoErrorf(t, err, "Error when installing agent, output: %s", out)

	// Wait for the agent to connect to Fleet and report HEALTHY.
	check.ConnectedToFleet(ctx, t, fixture, 5*time.Minute)

	// Deliver an UNINSTALL action on the next checkin.
	uninstallActionID := "uninstall-action-id"
	uninstallAction, err := fleetservertest.NewAction(fleetservertest.ActionTmpl{
		AgentID:  policy.AgentID,
		ActionID: uninstallActionID,
		Type:     fleetapi.ActionTypeUninstall,
		Data:     "{}",
	})
	require.NoError(t, err, "failed to create uninstall action")
	checkinWithAcker.AddCheckin("token", 1*time.Second, uninstallAction)

	// The UNINSTALL action is acknowledged by the detached uninstaller at the
	// point of no return: after the agent's service and components have been
	// removed, but before its credentials are removed. Because the uninstall is
	// terminal, a received ack proves the full spawn -> uninstall -> point-of-
	// no-return-ack flow worked end-to-end with Fleet Server.
	require.EventuallyWithT(t, func(collect *assert.CollectT) {
		assert.True(collect, checkinWithAcker.Acked(uninstallActionID),
			"uninstall action has not been acknowledged to Fleet")
	}, 5*time.Minute, 500*time.Millisecond, "agent did not acknowledge the uninstall action")

	// After acking, the uninstall completes and removes the install directory.
	// The agent must no longer be installed; a status check should fail once the
	// control socket is gone. This confirms the agent actually uninstalled itself
	// rather than merely acking.
	require.EventuallyWithT(t, func(collect *assert.CollectT) {
		_, statusErr := fixture.ExecStatus(ctx)
		assert.Error(collect, statusErr, "agent still responds to status; expected it to be uninstalled")
	}, 5*time.Minute, 1*time.Second, "agent was not uninstalled after acknowledging the action")
}
