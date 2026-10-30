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
	"os"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/pkg/fleetapi"
	integrationtest "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/tools/check"
	"github.com/elastic/elastic-agent/pkg/testing/tools/testcontext"
	"github.com/elastic/elastic-agent/testing/fleetservertest"
	"github.com/elastic/elastic-agent/testing/integration"
)

// ackRecorder records, per action id, whether the agent's acknowledgement
// carried an error, so a success ack can be distinguished from a failure ack
// (the mock's Acked only matches the action id and would accept either).
type ackRecorder struct {
	mu   sync.Mutex
	errs map[string]string // actionID -> error ("" means acknowledged without error)
}

func (r *ackRecorder) record(actionID, errMsg string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.errs == nil {
		r.errs = map[string]string{}
	}
	r.errs[actionID] = errMsg
}

// ackedWithoutError reports whether the action was acknowledged and its ack
// carried no error.
func (r *ackRecorder) ackedWithoutError(actionID string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	errMsg, ok := r.errs[actionID]
	return ok && errMsg == ""
}

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

	fixture, checkinWithAcker, recorder, policy := setupUninstallFleetServer(t, ctx)

	// Deliver an UNINSTALL action on the next checkin. The agent enforces a
	// grace-period window of [created_at+1h, created_at+24h] on the start_time.
	// The fleet gateway only triggers a dispatch when a checkin returns at least
	// one action; a scheduled action with a *future* start_time would otherwise
	// sit in the queue until the periodic (multi-minute) flush, racing this
	// test's timeout. So we stamp a start_time that is already in the past while
	// still inside the valid window (created_at backdated 2h, start_time 30m
	// ago): the action is due the moment it is received and is dequeued and
	// dispatched in the same cycle, exercising the full queue -> dispatch ->
	// detached uninstaller -> point-of-no-return ack flow without a long wait.
	base := time.Now()
	uninstallActionID := "uninstall-action-id"
	uninstallAction, err := fleetservertest.NewAction(fleetservertest.ActionTmpl{
		AgentID:   policy.AgentID,
		ActionID:  uninstallActionID,
		Type:      fleetapi.ActionTypeUninstall,
		CreatedAt: base.Add(-2 * time.Hour).UTC().Format(time.RFC3339),
		StartTime: base.Add(-30 * time.Minute).UTC().Format(time.RFC3339),
		Data:      `{}`,
	})
	require.NoError(t, err, "failed to create uninstall action")
	checkinWithAcker.AddCheckin("token", 1*time.Second, uninstallAction)

	// The UNINSTALL action is acknowledged by the detached uninstaller at the
	// point of no return: after the agent's service and components have been
	// removed, but before its credentials are removed. Assert the ack carried NO
	// error — a failure before the point of no return would instead produce a
	// failure ack — so this proves the successful spawn -> uninstall ->
	// point-of-no-return-ack flow worked end-to-end with Fleet Server.
	require.EventuallyWithT(t, func(collect *assert.CollectT) {
		assert.True(collect, recorder.ackedWithoutError(uninstallActionID),
			"uninstall action was not acknowledged, or was acknowledged with an error")
	}, 5*time.Minute, 500*time.Millisecond, "agent did not acknowledge the uninstall action without error")

	// Independently confirm the agent actually uninstalled itself: the install
	// directory must be removed. Checking only that the control socket is gone is
	// insufficient — a stopped-but-still-installed agent also fails ExecStatus.
	installDir := paths.InstallPath(paths.DefaultBasePath)
	require.EventuallyWithT(t, func(collect *assert.CollectT) {
		_, statErr := os.Stat(installDir)
		assert.Truef(collect, os.IsNotExist(statErr),
			"install directory %q still exists; agent was acked but not fully uninstalled (stat err: %v)", installDir, statErr)
		_, statusErr := fixture.ExecStatus(ctx)
		assert.Error(collect, statusErr, "agent still responds to status; expected it to be uninstalled")
	}, 5*time.Minute, 1*time.Second, "agent was not uninstalled after acknowledging the action")
}

// TestFleetUninstallActionCancelled validates that a Fleet CANCEL action delivered
// during the UNINSTALL grace period cancels the pending uninstall: the agent keeps
// running and is never removed.
func TestFleetUninstallActionCancelled(t *testing.T) {
	_ = define.Require(t, define.Requirements{
		Group: integration.Fleet,
		Stack: &define.Stack{},
		Local: false, // requires Agent installation
		Sudo:  true,  // requires Agent installation
	})

	ctx, cancel := testcontext.WithTimeout(t, t.Context(), time.Minute*10)
	defer cancel()

	fixture, checkinWithAcker, _, policy := setupUninstallFleetServer(t, ctx)

	// Deliver an UNINSTALL action with a *future* start_time so it is held in the
	// scheduled-action queue, giving the cancel below a window to remove it before
	// it executes. created_at is backdated 1h so the start_time stays inside the
	// agent's [created_at+1h, created_at+24h] grace-period window.
	//
	// Unlike TestFleetUninstallAction (which needs an already-due start_time so the
	// action is dispatched on the delivering checkin), a future start_time is
	// correct here: the fleet gateway only triggers a dispatch when a checkin
	// returns at least one action, and the CANCEL action delivered below is
	// exactly such a trigger — its arrival re-runs the dispatcher, which removes
	// the still-queued uninstall from the queue. So the cancel never depends on
	// the periodic queue flush.
	base := time.Now()
	uninstallActionID := "uninstall-action-id"
	uninstallAction, err := fleetservertest.NewAction(fleetservertest.ActionTmpl{
		AgentID:   policy.AgentID,
		ActionID:  uninstallActionID,
		Type:      fleetapi.ActionTypeUninstall,
		CreatedAt: base.Add(-1 * time.Hour).UTC().Format(time.RFC3339),
		StartTime: base.Add(1 * time.Minute).UTC().Format(time.RFC3339),
		Data:      `{}`,
	})
	require.NoError(t, err, "failed to create uninstall action")
	checkinWithAcker.AddCheckin("token", 1*time.Second, uninstallAction)

	// While the uninstall waits out its grace period in the queue, the agent
	// surfaces an "Uninstall pending" state. Wait for it so we know the action was
	// received and queued before we cancel it. (CANCEL actions are not
	// acknowledged by the agent, so cancellation is verified via this observable
	// state rather than an ack.)
	require.EventuallyWithT(t, func(collect *assert.CollectT) {
		status, statusErr := fixture.ExecStatus(ctx)
		assert.NoError(collect, statusErr)
		assert.Contains(collect, status.Message, "Uninstall pending",
			"agent did not report the uninstall as pending")
	}, 3*time.Minute, 1*time.Second, "agent never reported the uninstall as pending")

	// Cancel it before the grace period elapses by targeting the uninstall action
	// id. The CANCEL delivery is itself a checkin that returns an action, which
	// re-runs the dispatcher and removes the still-queued uninstall from the queue
	// (dispatchCancelActions runs before queued actions are dequeued, so the
	// cancel wins even if the start_time has just elapsed).
	cancelActionID := "cancel-action-id"
	cancelAction, err := fleetservertest.NewAction(fleetservertest.ActionTmpl{
		AgentID:  policy.AgentID,
		ActionID: cancelActionID,
		Type:     fleetapi.ActionTypeCancel,
		Data:     fmt.Sprintf(`{"target_id":%q}`, uninstallActionID),
	})
	require.NoError(t, err, "failed to create cancel action")
	checkinWithAcker.AddCheckin("token", 1*time.Second, cancelAction)

	// Once the cancel is processed the pending uninstall is removed from the queue
	// and the agent clears the "Uninstall pending" state. This confirms the cancel
	// took effect.
	require.EventuallyWithT(t, func(collect *assert.CollectT) {
		status, statusErr := fixture.ExecStatus(ctx)
		assert.NoError(collect, statusErr)
		assert.NotContains(collect, status.Message, "Uninstall pending",
			"agent still reports the uninstall as pending after the cancel")
	}, 3*time.Minute, 1*time.Second, "agent did not clear the pending uninstall after the cancel")

	// The uninstall must never be acknowledged (it was removed from the queue) —
	// proving the cancel prevented it from ever executing.
	require.Never(t, func() bool {
		return checkinWithAcker.Acked(uninstallActionID)
	}, 30*time.Second, 5*time.Second, "uninstall action was acknowledged despite being cancelled")

	// The agent must still be installed and responding to status.
	_, statusErr := fixture.ExecStatus(ctx)
	require.NoError(t, statusErr, "agent should still be installed after the uninstall was cancelled")
}

// setupUninstallFleetServer starts a mock Fleet Server that serves queued actions
// via checkinWithAcker, installs a privileged agent enrolled against it, and waits
// for the agent to connect. UNINSTALL requires root/administrator privileges (an
// unprivileged agent's service runs as a non-root user and cannot remove its own
// service), so the agent is installed privileged.
func setupUninstallFleetServer(t *testing.T, ctx context.Context) (*integrationtest.Fixture, *fleetservertest.CheckinActionsWithAcker, *ackRecorder, fleetservertest.TmplPolicy) {
	t.Helper()

	apiKey, policy := createBasicFleetPolicyData(t, "http://fleet-server:8221")
	checkinWithAcker := fleetservertest.NewCheckinActionsWithAcker()
	nextActionGenerator := checkinWithAcker.ActionsGenerator()
	recorder := &ackRecorder{}
	ackHandler := fleetservertest.NewHandlerAckWithAcker(checkinWithAcker.Acker())

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
		AckFn: func(ctx context.Context, h *fleetservertest.Handlers, agentID string,
			ackRequest fleetservertest.AckRequest,
		) (*fleetservertest.AckResponse, *fleetservertest.HTTPError) {
			// Record each ack's error so the test can tell a success ack from a
			// failure ack, then delegate to the standard acker-backed handler.
			for _, e := range ackRequest.Events {
				recorder.record(e.ActionId, e.Error)
			}
			return ackHandler(ctx, h, agentID, ackRequest)
		},
		StatusFn: fleetservertest.NewHandlerStatusHealthy(),
	}

	fleetServer := fleetservertest.NewServer(handlers, fleetservertest.WithRequestLog(t.Logf))
	t.Cleanup(fleetServer.Close)

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
			Privileged:     true,
			EnrollOpts: integrationtest.EnrollOpts{
				URL:             fleetServer.LocalhostURL,
				EnrollmentToken: "anythingWillDO",
			}})
	require.NoErrorf(t, err, "Error when installing agent, output: %s", out)

	// Wait for the agent to connect to Fleet and report HEALTHY.
	check.ConnectedToFleet(ctx, t, fixture, 5*time.Minute)

	return fixture, &checkinWithAcker, recorder, policy
}
