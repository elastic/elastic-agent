// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package cmd

import (
	"fmt"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"go.uber.org/zap/zapcore"

	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/details"
	"github.com/elastic/elastic-agent/internal/pkg/agent/configuration"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi"
	"github.com/elastic/elastic-agent/internal/pkg/release"
	"github.com/elastic/elastic-agent/pkg/core/logger/loggertest"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade"
	cmdmocks "github.com/elastic/elastic-agent/testing/mocks/internal_/pkg/agent/cmd"
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

func Test_watchCmd(t *testing.T) {
	type args struct {
		cfg *configuration.UpgradeWatcherConfig
	}
	tests := []struct {
		name               string
		setupUpgradeMarker func(t *testing.T, tmpDir string, watcher *cmdmocks.AgentWatcher, installModifier *cmdmocks.InstallationModifier)
		args               args
		wantErr            assert.ErrorAssertionFunc
	}{
		{
			name: "no upgrade marker, no party",
			setupUpgradeMarker: func(t *testing.T, topDir string, watcher *cmdmocks.AgentWatcher, installModifier *cmdmocks.InstallationModifier) {
				dataDirPath := paths.DataFrom(topDir)
				err := os.MkdirAll(dataDirPath, 0755)
				require.NoError(t, err)
			},
			args: args{
				cfg: configuration.DefaultUpgradeConfig().Watcher,
			},
			wantErr: assert.NoError,
		},
		{
			name: "happy path: no error watching, cleanup prev install",
			setupUpgradeMarker: func(t *testing.T, topDir string, watcher *cmdmocks.AgentWatcher, installModifier *cmdmocks.InstallationModifier) {
				dataDirPath := paths.DataFrom(topDir)
				err := os.MkdirAll(dataDirPath, 0755)
				require.NoError(t, err)
				err = upgrade.SaveMarker(
					dataDirPath,
					&upgrade.UpdateMarker{
						Version:           "4.5.6",
						Hash:              "newver",
						VersionedHome:     "elastic-agent-4.5.6-newver",
						UpdatedOn:         time.Now(),
						PrevVersion:       "1.2.3",
						PrevHash:          "prvver",
						PrevVersionedHome: "elastic-agent-prvver",
						Acked:             false,
						Action:            nil,
						Details:           nil, //details.NewDetails("4.5.6", details.StateReplacing, ""),
						DesiredOutcome:    upgrade.OUTCOME_UPGRADE,
					},
					true,
				)
				require.NoError(t, err)

				watcher.EXPECT().
					Watch(mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return(nil)

				expectedRemoveMarkerFlag := true
				if runtime.GOOS == "windows" {
					// on windows the marker is not removed immediately to allow for cleanup on restart
					expectedRemoveMarkerFlag = false
				}
				installModifier.EXPECT().
					Cleanup(mock.Anything, topDir, "elastic-agent-4.5.6-newver", "newver", expectedRemoveMarkerFlag, false).
					Return(nil)
			},
			args: args{
				cfg: configuration.DefaultUpgradeConfig().Watcher,
			},
			wantErr: assert.NoError,
		},
		{
			name: "unhappy path: error watching, rollback to previous install",
			setupUpgradeMarker: func(t *testing.T, topDir string, watcher *cmdmocks.AgentWatcher, installModifier *cmdmocks.InstallationModifier) {
				dataDirPath := paths.DataFrom(topDir)
				err := os.MkdirAll(dataDirPath, 0755)
				require.NoError(t, err)
				err = upgrade.SaveMarker(
					dataDirPath,
					&upgrade.UpdateMarker{
						Version:           "4.5.6",
						Hash:              "newver",
						VersionedHome:     "elastic-agent-4.5.6-newver",
						UpdatedOn:         time.Now(),
						PrevVersion:       "1.2.3",
						PrevHash:          "prvver",
						PrevVersionedHome: "elastic-agent-prvver",
						Acked:             false,
						Action:            nil,
						Details:           nil, //details.NewDetails("4.5.6", details.StateReplacing, ""),
						DesiredOutcome:    upgrade.OUTCOME_UPGRADE,
					},
					true,
				)
				require.NoError(t, err)

				watcher.EXPECT().
					Watch(mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return(errors.New("some watch error due to agent misbehaving"))
				installModifier.EXPECT().
					Rollback(mock.Anything, mock.Anything, mock.Anything, paths.Top(), "elastic-agent-prvver", "prvver").
					Return(nil)
			},
			args: args{
				cfg: configuration.DefaultUpgradeConfig().Watcher,
			},
			wantErr: assert.NoError,
		},
		{
			name: "upgrade rolled back: no watching, cleanup must be called",
			setupUpgradeMarker: func(t *testing.T, topDir string, watcher *cmdmocks.AgentWatcher, installModifier *cmdmocks.InstallationModifier) {
				dataDirPath := paths.DataFrom(topDir)
				err := os.MkdirAll(dataDirPath, 0755)
				require.NoError(t, err)
				err = upgrade.SaveMarker(
					dataDirPath,
					&upgrade.UpdateMarker{
						Version:           "4.5.6",
						Hash:              "newver",
						VersionedHome:     "elastic-agent-4.5.6-newver",
						UpdatedOn:         time.Now(),
						PrevVersion:       "1.2.3",
						PrevHash:          "prvver",
						PrevVersionedHome: "elastic-agent-prvver",
						Acked:             false,
						Action:            nil,
						Details: &details.Details{
							TargetVersion: "4.5.6",
							State:         details.StateRollback,
							Metadata: details.Metadata{
								Reason: "automatic rollback",
							},
						},
						DesiredOutcome: upgrade.OUTCOME_UPGRADE,
					},
					true,
				)
				require.NoError(t, err)
				// topdir, prevVersionedHome and prevHash are not taken from the upgrade marker, otherwise they would be
				// <topDir, "topDir/data/elastic-agent-prvver", "prvver">
				installModifier.EXPECT().
					Cleanup(mock.Anything, paths.Top(), paths.VersionedHome(topDir), release.ShortCommit(), true, false).
					Return(nil)
			},
			args: args{
				cfg: configuration.DefaultUpgradeConfig().Watcher,
			},
			wantErr: assert.NoError,
		},
		{
			name: "after grace period: no watching, cleanup must be called",
			setupUpgradeMarker: func(t *testing.T, topDir string, watcher *cmdmocks.AgentWatcher, installModifier *cmdmocks.InstallationModifier) {
				dataDirPath := paths.DataFrom(topDir)
				err := os.MkdirAll(dataDirPath, 0755)
				require.NoError(t, err)
				updatedOn := time.Now().Add(-5 * time.Minute)
				err = upgrade.SaveMarker(
					dataDirPath,
					&upgrade.UpdateMarker{
						Version:           "4.5.6",
						Hash:              "newver",
						VersionedHome:     "elastic-agent-4.5.6-newver",
						UpdatedOn:         updatedOn,
						PrevVersion:       "1.2.3",
						PrevHash:          "prvver",
						PrevVersionedHome: "elastic-agent-prvver",
						Acked:             false,
						Action:            nil,
						Details:           nil,
						DesiredOutcome:    upgrade.OUTCOME_UPGRADE,
					},
					true,
				)
				require.NoError(t, err)

				// topdir, prevVersionedHome and prevHash are not taken from the upgrade marker, otherwise they would be
				// <topDir, "topDir/data/elastic-agent-prvver", "prvver">
				installModifier.EXPECT().
					Cleanup(mock.Anything, paths.Top(), paths.VersionedHome(topDir), release.ShortCommit(), true, false).
					Return(nil)
			},
			args: args{
				cfg: &configuration.UpgradeWatcherConfig{
					GracePeriod: 2 * time.Minute,
					ErrorCheck: configuration.UpgradeWatcherCheckConfig{
						Interval: time.Second,
					},
				},
			},
			wantErr: assert.NoError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			log, obs := loggertest.New(t.Name())
			tmpDir := t.TempDir()
			mockWatcher := cmdmocks.NewAgentWatcher(t)
			mockInstallModifier := cmdmocks.NewInstallationModifier(t)
			tt.setupUpgradeMarker(t, tmpDir, mockWatcher, mockInstallModifier)
			tt.wantErr(t, watchCmd(log, tmpDir, tt.args.cfg, mockWatcher, mockInstallModifier), fmt.Sprintf("watchCmd(%v, ...)", tt.args.cfg))
			t.Logf("watchCmd logs:\n%v", obs.All())
		})
	}
}
