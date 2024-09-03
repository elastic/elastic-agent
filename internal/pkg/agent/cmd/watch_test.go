// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package cmd

import (
	"testing"

	"go.uber.org/zap/zapcore"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/details"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi"

	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade"
)

func TestInitUpgradeDetails(t *testing.T) {
	testMarker := &upgrade.UpdateMarker{
		Action: &fleetapi.ActionUpgrade{
			ActionID: "foobar",
		},
	}

	saveCount := 0
	mockSaveMarker := func(marker *upgrade.UpdateMarker, _ bool) error {
		saveCount++
		if saveCount <= 3 {
			testMarker = marker
			return nil
		}
		return errors.New("some error")
	}

	log, obs := loggertest.New("initUpgradeDetails")

	upgradeDetails := initUpgradeDetails(testMarker, mockSaveMarker, log)

	// Verify initial state
	require.NotNil(t, testMarker.Details)
	require.Equal(t, details.StateWatching, testMarker.Details.State)
	require.Equal(t, 0, obs.Len())

	// Verify state after changing details state
	upgradeDetails.SetState(details.StateRollback)
	require.NotNil(t, testMarker.Details)
	require.Equal(t, details.StateRollback, testMarker.Details.State)
	require.Equal(t, 0, obs.Len())

	// Verify state after clearing details state
	upgradeDetails.SetState(details.StateCompleted)
	require.Nil(t, testMarker.Details)
	require.Equal(t, 0, obs.Len())

	// Verify state after changing details state and there's an
	// error saving the marker
	upgradeDetails.SetState(details.StateRollback)
	require.NotNil(t, testMarker.Details)
	require.Equal(t, 1, obs.Len())
	logs := obs.TakeAll()
	require.Equal(t, zapcore.ErrorLevel, logs[0].Level)
	require.Equal(t, `unable to save upgrade marker after setting upgrade details (state = UPG_ROLLBACK): some error`, logs[0].Message)

	// Verify state after clearing details state and there's an
	// error saving the marker
	upgradeDetails.SetState(details.StateCompleted)
	require.Nil(t, testMarker.Details)
	require.Equal(t, 1, obs.Len())
	logs = obs.TakeAll()
	require.Equal(t, zapcore.ErrorLevel, logs[0].Level)
	require.Equal(t, `unable to save upgrade marker after clearing upgrade details: some error`, logs[0].Message)
}
