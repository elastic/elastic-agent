// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package upgrade

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest/observer"

	"github.com/elastic/elastic-agent/pkg/core/logger"
)

func TestFSM(t *testing.T) {
	l, obs := logger.NewTesting("upgrade_fsm")

	var cbCallCounter atomic.Int64
	cb := func(oldState, newState, action string) {
		cbCallCounter.Add(1)
	}

	fsm := NewFSM(l, cb)
	require.Equal(t, int64(0), cbCallCounter.Load())

	// Test that valid transitions succeed
	t.Run("valid_transition", func(t *testing.T) {
		// UPG_REQUESTED ─── scheduling ───> UPG_SCHEDULED
		err := fsm.Transition(context.Background(), ActionScheduling)
		verifyValidTransition(t, fsm, obs, err, cbCallCounter.Load(), StateRequested, StateScheduled, 1)

		// UPG_SCHEDULED ─── succeeded ───> UPG_DOWNLOADING
		err = fsm.Transition(context.Background(), ActionSucceeded)
		verifyValidTransition(t, fsm, obs, err, cbCallCounter.Load(), StateScheduled, StateDownloading, 2)

		// UPG_DOWNLOADING ─── failed ───> UPG_FAILED
		err = fsm.Transition(context.Background(), ActionFailed)
		verifyValidTransition(t, fsm, obs, err, cbCallCounter.Load(), StateDownloading, StateFailed, 3)
	})

	// Test that an invalid transition returns error
	t.Run("invalid_transition", func(t *testing.T) {
		// UPG_FAILED ─── rolling_back ───> error
		err := fsm.Transition(context.Background(), ActionRollingBack)
		require.Error(t, err)
		require.EqualError(t, err, fmt.Sprintf(
			"unable to transition from [%[1]s] with action [%[2]s]: event %[2]s inappropriate in current state %[1]s",
			StateFailed, ActionRollingBack,
		))
		require.Equal(t, int64(3), cbCallCounter.Load())
		require.Equal(t, 0, obs.Len())
	})
}

func verifyValidTransition(
	t *testing.T,
	upgradeFSM *FSM, obs *observer.ObservedLogs,
	actualErr error, actualCBCallCounter int64,
	expectedStartState, expectedEndState string,
	expectedCBCallCounter int64,
) {
	t.Helper()

	require.NoError(t, actualErr)
	require.Equal(t, expectedEndState, upgradeFSM.Current())
	require.Equal(t, 1, obs.Len())
	require.Equal(t, expectedCBCallCounter, actualCBCallCounter)

	log := obs.TakeAll()[0]
	require.Equal(t, "transitioning upgrade state machine", log.Message)
	require.Equal(t, "from", log.Context[0].Key)
	require.Equal(t, expectedStartState, log.Context[0].String)
	require.Equal(t, "to", log.Context[1].Key)
	require.Equal(t, expectedEndState, log.Context[1].String)
}
