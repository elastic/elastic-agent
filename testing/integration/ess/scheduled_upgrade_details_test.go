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

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/details"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi"
	integrationtest "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/tools/check"
	"github.com/elastic/elastic-agent/pkg/testing/tools/testcontext"
	"github.com/elastic/elastic-agent/testing/fleetservertest"
	"github.com/elastic/elastic-agent/testing/integration"
)

func TestFleetScheduledUpgrade(t *testing.T) {
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

	var checkInRequest struct {
		sync.Mutex
		updatedTime    time.Time
		UpgradeDetails *details.Details
	}

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

			checkInRequest.Lock()
			checkInRequest.updatedTime = time.Now()
			checkInRequest.UpgradeDetails = checkinRequest.UpgradeDetails
			checkInRequest.Unlock()

			data, hErr := nextActionGenerator()
			if hErr != nil {
				return nil, hErr
			}

			respStr := fleetservertest.NewCheckinResponse(data.AckToken, data.Actions...)
			resp := fleetservertest.CheckinResponse{}
			err := json.Unmarshal(
				[]byte(respStr),
				&resp)
			if err != nil {
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
			Privileged:     false,
			EnrollOpts: integrationtest.EnrollOpts{
				URL:             fleetServer.LocalhostURL,
				EnrollmentToken: "anythingWillDO",
			}})
	require.NoErrorf(t, err, "Error when installing agent, output: %s", out)

	// Wait for the agent to connect to Fleet and report HEALTHY
	check.ConnectedToFleet(ctx, t, fixture, 5*time.Minute)

	// Simulate a scheduled upgrade action
	targetVersion := "255.0.0"
	t.Run("scheduled upgrade action", func(t *testing.T) {
		scheduledActionUUID := "scheduled-action-id"
		scheduledUpgradeAction, err := fleetservertest.NewAction(fleetservertest.ActionTmpl{
			AgentID:   policy.AgentID,
			ActionID:  scheduledActionUUID,
			Type:      fleetapi.ActionTypeUpgrade,
			Data:      fmt.Sprintf(`{"version": "%s"}`, targetVersion),
			StartTime: time.Now().Add(time.Hour).Format(time.RFC3339),
		})
		require.NoError(t, err, "failed to create scheduled upgrade action")
		checkinWithAcker.AddCheckin("token", 1*time.Second, scheduledUpgradeAction)

		// Wait and check that elastic-agent has reported the scheduled upgrade
		// in the upgrade details
		require.EventuallyWithT(t, func(collect *assert.CollectT) {
			checkInRequest.Lock()
			defer checkInRequest.Unlock()
			if !assert.NotNil(collect, checkInRequest.UpgradeDetails) {
				return
			}
			assert.Equal(collect, targetVersion, checkInRequest.UpgradeDetails.TargetVersion)
			assert.EqualValues(collect, details.StateScheduled, checkInRequest.UpgradeDetails.State)
			assert.Equal(collect, scheduledActionUUID, checkInRequest.UpgradeDetails.ActionID)
		}, 5*time.Minute, 500*time.Millisecond, "agent did not report scheduled upgrade")

		// Deliberately restart elastic-agent to check that it still reports
		// correctly the scheduled upgrade details
		restartAgentNTimes(t, 3, 300*time.Millisecond)

		// Wait and check that elastic-agent has a more recent checkin with
		// the correct upgrade details
		timeSnapshot := time.Now()
		require.EventuallyWithT(t, func(collect *assert.CollectT) {
			checkInRequest.Lock()
			defer checkInRequest.Unlock()
			if !assert.NotNil(collect, checkInRequest.UpgradeDetails) {
				return
			}
			assert.Less(collect, timeSnapshot, checkInRequest.updatedTime)
			assert.Equal(collect, targetVersion, checkInRequest.UpgradeDetails.TargetVersion)
			assert.EqualValues(collect, details.StateScheduled, checkInRequest.UpgradeDetails.State)
			assert.Equal(collect, scheduledActionUUID, checkInRequest.UpgradeDetails.ActionID)
		}, 5*time.Minute, 500*time.Millisecond, "agent did not report scheduled upgrade after restart")

		// Simulate a cancel action of the scheduled upgrade
		cancelActionUUID := "cancel-action-id"
		cancelAction, err := fleetservertest.NewAction(fleetservertest.ActionTmpl{
			AgentID:  policy.AgentID,
			Type:     fleetapi.ActionTypeCancel,
			ActionID: cancelActionUUID,
			Data:     fmt.Sprintf(`{"target_id": "%s"}`, scheduledActionUUID),
		})
		checkinWithAcker.AddCheckin("token", 1*time.Second, cancelAction)

		// Wait and check that elastic-agent has reported a more recent checkin
		// with empty upgrade details
		timeSnapshot = time.Now()
		require.EventuallyWithT(t, func(collect *assert.CollectT) {
			checkInRequest.Lock()
			defer checkInRequest.Unlock()
			assert.Less(collect, timeSnapshot, checkInRequest.updatedTime)
			assert.Nil(collect, checkInRequest.UpgradeDetails)
		}, 5*time.Minute, 500*time.Millisecond, "agent did not report empty upgrade details after cancel")
	})

	t.Run("expired scheduled upgrade action", func(t *testing.T) {
		scheduledExpiredActionUUID := "expired-scheduled-action-id"
		scheduledExpiredUpgradeAction, err := fleetservertest.NewAction(fleetservertest.ActionTmpl{
			AgentID:    policy.AgentID,
			ActionID:   scheduledExpiredActionUUID,
			Type:       fleetapi.ActionTypeUpgrade,
			Data:       fmt.Sprintf(`{"version": "%s"}`, targetVersion),
			StartTime:  time.Now().Add(-time.Hour).Format(time.RFC3339),
			Expiration: time.Now().Add(-time.Hour).Format(time.RFC3339),
		})
		require.NoError(t, err, "failed to create expired scheduled upgrade action")
		checkinWithAcker.AddCheckin("token", 1*time.Second, scheduledExpiredUpgradeAction)

		// Wait and check that elastic-agent has reported the expired scheduled upgrade
		// in the upgrade details
		require.EventuallyWithT(t, func(collect *assert.CollectT) {
			checkInRequest.Lock()
			defer checkInRequest.Unlock()
			if !assert.NotNil(collect, checkInRequest.UpgradeDetails) {
				return
			}
			assert.Equal(collect, targetVersion, checkInRequest.UpgradeDetails.TargetVersion)
			assert.EqualValues(collect, details.StateFailed, checkInRequest.UpgradeDetails.State)
			assert.Equal(collect, scheduledExpiredActionUUID, checkInRequest.UpgradeDetails.ActionID)
		}, 5*time.Minute, 500*time.Millisecond, "agent did not report expired scheduled upgrade")

		// Deliberately restart elastic-agent to check that it still reports
		// correctly the expired scheduled upgrade details
		restartAgentNTimes(t, 3, 300*time.Millisecond)

		// Wait and check that elastic-agent has a more recent checkin with
		// the correct upgrade details
		timeSnapshot := time.Now()
		require.EventuallyWithT(t, func(collect *assert.CollectT) {
			checkInRequest.Lock()
			defer checkInRequest.Unlock()
			if !assert.NotNil(collect, checkInRequest.UpgradeDetails) {
				return
			}
			assert.Less(collect, timeSnapshot, checkInRequest.updatedTime)
			assert.Equal(collect, targetVersion, checkInRequest.UpgradeDetails.TargetVersion)
			assert.EqualValues(collect, details.StateFailed, checkInRequest.UpgradeDetails.State)
			assert.Equal(collect, scheduledExpiredActionUUID, checkInRequest.UpgradeDetails.ActionID)
		}, 5*time.Minute, 500*time.Millisecond, "agent did not report expired scheduled upgrade after restart")

		// Simulate a cancel action of the scheduled upgrade
		cancelExpiredActionUUID := "cancel-expired-action-id"
		cancelExpiredAction, err := fleetservertest.NewAction(fleetservertest.ActionTmpl{
			AgentID:  policy.AgentID,
			Type:     fleetapi.ActionTypeCancel,
			ActionID: cancelExpiredActionUUID,
			Data:     fmt.Sprintf(`{"target_id": "%s"}`, scheduledExpiredActionUUID),
		})
		checkinWithAcker.AddCheckin("token", 1*time.Second, cancelExpiredAction)

		// Wait and check that elastic-agent has reported a more recent checkin
		// with empty upgrade details
		timeSnapshot = time.Now()
		require.EventuallyWithT(t, func(collect *assert.CollectT) {
			checkInRequest.Lock()
			defer checkInRequest.Unlock()
			assert.Less(collect, timeSnapshot, checkInRequest.updatedTime)
			assert.Nil(collect, checkInRequest.UpgradeDetails)
		}, 5*time.Minute, 500*time.Millisecond, "agent did not report empty upgrade details after cancel")
	})

	t.Run("initially expired scheduled upgrade action receive new upgrade action", func(t *testing.T) {
		scheduledExpiredActionUUID := "expired-scheduled-action-id"
		scheduledExpiredUpgradeAction, err := fleetservertest.NewAction(fleetservertest.ActionTmpl{
			AgentID:    policy.AgentID,
			ActionID:   scheduledExpiredActionUUID,
			Type:       fleetapi.ActionTypeUpgrade,
			Data:       fmt.Sprintf(`{"version": "%s"}`, targetVersion),
			StartTime:  time.Now().Add(-time.Hour).Format(time.RFC3339),
			Expiration: time.Now().Add(-time.Hour).Format(time.RFC3339),
		})
		require.NoError(t, err, "failed to create expired scheduled upgrade action")
		checkinWithAcker.AddCheckin("token", 1*time.Second, scheduledExpiredUpgradeAction)

		// Wait and check that elastic-agent has reported the expired scheduled upgrade
		// in the upgrade details
		require.EventuallyWithT(t, func(collect *assert.CollectT) {
			checkInRequest.Lock()
			defer checkInRequest.Unlock()
			if !assert.NotNil(collect, checkInRequest.UpgradeDetails) {
				return
			}
			assert.Equal(collect, targetVersion, checkInRequest.UpgradeDetails.TargetVersion)
			assert.EqualValues(collect, details.StateFailed, checkInRequest.UpgradeDetails.State)
			assert.Equal(collect, scheduledExpiredActionUUID, checkInRequest.UpgradeDetails.ActionID)
		}, 5*time.Minute, 500*time.Millisecond, "agent did not report expired scheduled upgrade")

		// send a new scheduled action through the checkin
		scheduledActionUUID := "scheduled-action-id"
		scheduledUpgradeAction, err := fleetservertest.NewAction(fleetservertest.ActionTmpl{
			AgentID:   policy.AgentID,
			ActionID:  scheduledActionUUID,
			Type:      fleetapi.ActionTypeUpgrade,
			Data:      fmt.Sprintf(`{"version": "%s"}`, targetVersion),
			StartTime: time.Now().Add(time.Hour).Format(time.RFC3339),
		})
		require.NoError(t, err, "failed to create scheduled upgrade action")
		checkinWithAcker.AddCheckin("token", 1*time.Second, scheduledUpgradeAction)

		// Wait and check that elastic-agent has reported the scheduled upgrade
		// in the upgrade details
		require.EventuallyWithT(t, func(collect *assert.CollectT) {
			checkInRequest.Lock()
			defer checkInRequest.Unlock()
			if !assert.NotNil(collect, checkInRequest.UpgradeDetails) {
				return
			}
			assert.Equal(collect, targetVersion, checkInRequest.UpgradeDetails.TargetVersion)
			assert.EqualValues(collect, details.StateScheduled, checkInRequest.UpgradeDetails.State)
			assert.Equal(collect, scheduledActionUUID, checkInRequest.UpgradeDetails.ActionID)
		}, 5*time.Minute, 500*time.Millisecond, "agent did not report scheduled upgrade")

		// Deliberately restart elastic-agent to check that it still reports
		// correctly the scheduled upgrade details
		restartAgentNTimes(t, 3, 300*time.Millisecond)

		// Wait and check that elastic-agent has a more recent checkin with
		// the correct upgrade details
		timeSnapshot := time.Now()
		require.EventuallyWithT(t, func(collect *assert.CollectT) {
			checkInRequest.Lock()
			defer checkInRequest.Unlock()
			if !assert.NotNil(collect, checkInRequest.UpgradeDetails) {
				return
			}
			assert.Less(collect, timeSnapshot, checkInRequest.updatedTime)
			assert.Equal(collect, targetVersion, checkInRequest.UpgradeDetails.TargetVersion)
			assert.EqualValues(collect, details.StateScheduled, checkInRequest.UpgradeDetails.State)
			assert.Equal(collect, scheduledActionUUID, checkInRequest.UpgradeDetails.ActionID)
		}, 5*time.Minute, 500*time.Millisecond, "agent did not report scheduled upgrade after restart")

		// Simulate a cancel action of the scheduled upgrade
		cancelActionUUID := "cancel-action-id"
		cancelAction, err := fleetservertest.NewAction(fleetservertest.ActionTmpl{
			AgentID:  policy.AgentID,
			Type:     fleetapi.ActionTypeCancel,
			ActionID: cancelActionUUID,
			Data:     fmt.Sprintf(`{"target_id": "%s"}`, scheduledActionUUID),
		})
		checkinWithAcker.AddCheckin("token", 1*time.Second, cancelAction)

		// Wait and check that elastic-agent has reported a more recent checkin
		// with empty upgrade details
		timeSnapshot = time.Now()
		require.EventuallyWithT(t, func(collect *assert.CollectT) {
			checkInRequest.Lock()
			defer checkInRequest.Unlock()
			assert.Less(collect, timeSnapshot, checkInRequest.updatedTime)
			assert.Nil(collect, checkInRequest.UpgradeDetails)
		}, 5*time.Minute, 500*time.Millisecond, "agent did not report empty upgrade details after cancel")
	})

}
