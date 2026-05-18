// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package upgrade

import (
	"errors"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/details"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi"
	"github.com/elastic/elastic-agent/pkg/core/logger"
	"github.com/elastic/elastic-agent/pkg/core/logger/loggertest"
)

func TestTryLoadMarker_CorruptMarker(t *testing.T) {
	// Simulate a power loss mid-write: the action line is cut off inside a
	// flow mapping, leaving an unclosed string that yaml.Unmarshal rejects.
	const truncatedMarkerYAML = `version: 9.0.0
hash: a1b2c3
versioned_home: data/elastic-agent-9.0.0-a1b2c3
updated_on: 2026-04-20T10:00:00Z
prev_version: 8.17.6
action: {id: "fleet-action-abc1`

	log, _ := loggertest.New(t.Name())
	dataDir := t.TempDir()
	markerFile := markerFilePath(dataDir)
	require.NoError(t, os.WriteFile(markerFile, []byte(truncatedMarkerYAML), 0600))

	marker, err := TryLoadMarker(log, dataDir)
	require.NoError(t, err, "truncated marker must not cause a startup error")
	require.Nil(t, marker, "truncated marker must return nil so startup can continue")
	require.NoFileExists(t, markerFile, "corrupt marker file must have been moved aside")
	require.FileExists(t, markerFile+".corrupt", "corrupt marker must be preserved for diagnostics")
}

func TestTryLoadMarker_MissingFile(t *testing.T) {
	log, _ := loggertest.New(t.Name())
	marker, err := TryLoadMarker(log, t.TempDir())
	require.NoError(t, err)
	require.Nil(t, marker)
}

func TestCleanMarker_MissingMarkerIsOK(t *testing.T) {
	dataDir := t.TempDir()

	log, _ := loggertest.New(t.Name())
	require.NoError(t, CleanMarker(log, dataDir))
}

func TestMarkUpgrade(t *testing.T) {
	type args struct {
		currentAgent  agentInstall
		previousAgent agentInstall
		action        *fleetapi.ActionUpgrade
		details       *details.Details
	}
	type workingDirHook func(t *testing.T, dataDir string)

	testcases := []struct {
		name            string
		setupBeforeMark workingDirHook
		args            args
		wantErr         require.ErrorAssertionFunc
		assertAfterMark workingDirHook
	}{
		{
			name: "marker is written with all fields",
			args: args{
				currentAgent: agentInstall{
					version:       "8.5.0",
					hash:          "abc123",
					versionedHome: "home/v8.5.0",
				},
				previousAgent: agentInstall{
					version:       "8.4.0",
					hash:          "xyz789",
					versionedHome: "home/v8.4.0",
				},
				action:  nil,
				details: details.NewDetails("8.5.0", details.StateScheduled, ""),
			},
			wantErr: require.NoError,
			assertAfterMark: func(t *testing.T, dataDir string) {
				actualMarker, err := LoadMarker(dataDir)
				require.NoError(t, err, "error reading actualMarker content after writing")

				require.WithinDuration(t, time.Now(), actualMarker.UpdatedOn, 5*time.Second, "UpdatedOn mismatch")

				// Zero out UpdatedOn before full comparison: we cannot inject a
				// fixed timestamp in this branch (no updatedOn param on markUpgradeFunc).
				actualCopy := *actualMarker
				actualCopy.UpdatedOn = time.Time{}

				require.Equal(t, UpdateMarker{
					Version:           "8.5.0",
					Hash:              "abc123",
					VersionedHome:     "home/v8.5.0",
					PrevVersion:       "8.4.0",
					PrevHash:          "xyz789",
					PrevVersionedHome: "home/v8.4.0",
					Acked:             false,
					Action:            nil,
					Details: &details.Details{
						TargetVersion: "8.5.0",
						State:         "UPG_SCHEDULED",
						ActionID:      "",
						Metadata:      details.Metadata{},
					},
				}, actualCopy)
			},
		},
		{
			name: "error writing update marker - check error",
			setupBeforeMark: func(t *testing.T, dataDir string) {
				// read-only permissions on directories don't work on windows, skip
				if runtime.GOOS == "windows" {
					t.Skip("skipping test on windows since readonly permissions on directory don't work")
				}
				err := os.Chmod(dataDir, 0555)
				require.NoError(t, err, "error setting dataDir read-only")
			},
			args: args{
				currentAgent: agentInstall{
					version:       "8.5.0",
					hash:          "abc123",
					versionedHome: "home/v8.5.0",
				},
				previousAgent: agentInstall{
					version:       "8.4.0",
					hash:          "xyz789",
					versionedHome: "home/v8.4.0",
				},
				action:  nil,
				details: details.NewDetails("8.5.0", details.StateScheduled, ""),
			},
			wantErr: require.Error,
		},
	}

	// Use the regular markUpgrade function, disabling the updateActiveCommit
	// function that is bundled together (covered separately by TestUpdateActiveCommit).
	markUpgrade := markUpgradeProvider(
		func(log *logger.Logger, topDirPath, hash string, writeFile writeFileFunc) error {
			return nil
		},
		os.WriteFile,
	)

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			dataDir := t.TempDir()
			log, _ := loggertest.New(t.Name())

			if tc.setupBeforeMark != nil {
				tc.setupBeforeMark(t, dataDir)
			}

			err := markUpgrade(log, dataDir, tc.args.currentAgent, tc.args.previousAgent, tc.args.action, tc.args.details)
			tc.wantErr(t, err)
			if tc.assertAfterMark != nil {
				tc.assertAfterMark(t, dataDir)
			}
		})
	}
}

func TestUpdateActiveCommit(t *testing.T) {
	log, _ := loggertest.New("test")
	testError := errors.New("test error")
	testCases := map[string]struct {
		expectedError error
		writeFileFunc writeFileFunc
	}{
		"should return error if it fails writing to file": {
			expectedError: testError,
			writeFileFunc: func(name string, data []byte, perm os.FileMode) error {
				return testError
			},
		},
		"should not return error if it writes to file": {
			expectedError: nil,
			writeFileFunc: func(name string, data []byte, perm os.FileMode) error {
				return nil
			},
		},
	}
	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			err := UpdateActiveCommit(log, paths.Top(), "hash", tc.writeFileFunc)
			require.ErrorIs(t, err, tc.expectedError)
		})
	}

}
