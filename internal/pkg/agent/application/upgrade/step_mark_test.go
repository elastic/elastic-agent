// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package upgrade

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/details"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/ttl"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi"
	"github.com/elastic/elastic-agent/pkg/core/logger"
	"github.com/elastic/elastic-agent/pkg/core/logger/loggertest"
	agtversion "github.com/elastic/elastic-agent/pkg/version"
)

func TestSaveAndLoadMarker_NoLoss(t *testing.T) {
	// Create a temporary directory for the test
	tempDir := t.TempDir()
	markerFile := filepath.Join(tempDir, "test-marker.yaml")

	// Populate all fields of UpdateMarker
	originalMarker := &UpdateMarker{
		Version:           "8.5.0",
		Hash:              "abc123",
		VersionedHome:     "home/v8.5.0",
		UpdatedOn:         time.Now(),
		PrevVersion:       "8.4.0",
		PrevHash:          "xyz789",
		PrevVersionedHome: "home/v8.4.0",
		Acked:             true,
		Action: &fleetapi.ActionUpgrade{
			ActionID:   "action-123",
			ActionType: "UPGRADE",
			Data: fleetapi.ActionUpgradeData{
				Version:   "8.5.0",
				SourceURI: "https://example.com/upgrade",
			},
		},
		Details: details.NewDetails(
			"8.5.0",
			details.StateScheduled,
			"action-123"),
	}

	// Save the marker to the temporary file
	err := saveMarkerToPath(originalMarker, markerFile, true)
	require.NoError(t, err, "Failed to save marker")

	// Load the marker from the temporary file
	loadedMarker, err := loadMarker(markerFile)
	require.NoError(t, err, "Failed to load marker")

	// Compare time separately due to potential precision differences
	require.WithinDuration(t, originalMarker.UpdatedOn, loadedMarker.UpdatedOn, time.Second, "UpdatedOn mismatch")

	// Compare details separately to avoid issues with comparing observers
	require.True(t, originalMarker.Details.Equals(loadedMarker.Details), "Details mismatch")

	// Set the same time for deep comparison to avoid time precision issues
	originalMarkerCopy := *originalMarker
	originalMarkerCopy.UpdatedOn = loadedMarker.UpdatedOn

	originalMarkerCopy.Details = nil // Details are already compared separately
	loadedMarkerCopy := *loadedMarker
	loadedMarkerCopy.Details = nil // Details are already compared separately

	// Compare the rest of the fields
	require.Equal(t, originalMarkerCopy, loadedMarkerCopy, "Loaded marker does not match original marker")

	// Clean up the temporary file
	err = os.Remove(markerFile)
	require.NoError(t, err, "Failed to clean up marker file")
}

func TestMarkUpgrade(t *testing.T) {
	var parsed123SNAPSHOT = agtversion.NewParsedSemVer(1, 2, 3, "SNAPSHOT", "")
	var parsed456SNAPSHOT = agtversion.NewParsedSemVer(4, 5, 6, "SNAPSHOT", "")
	var parsed920SNAPSHOT = agtversion.NewParsedSemVer(9, 2, 0, "SNAPSHOT", "")
	// fix a timestamp (truncated to the second because of loss of precision during marshalling/unmarshalling)
	updatedOnNow := time.Now().UTC().Truncate(time.Second)
	twentyFourHoursFromNow := updatedOnNow.Add(24 * time.Hour)

	type args struct {
		updatedOn          time.Time
		currentAgent       agentInstall
		previousAgent      agentInstall
		action             *fleetapi.ActionUpgrade
		details            *details.Details
		availableRollbacks map[string]ttl.TTLMarker
	}
	type workingDirHook func(t *testing.T, dataDir string)

	testcases := []struct {
		name            string
		setupBeforeMark workingDirHook
		args            args
		wantErr         assert.ErrorAssertionFunc
		assertAfterMark workingDirHook
	}{
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
				updatedOn: updatedOnNow,
				currentAgent: agentInstall{
					parsedVersion: parsed456SNAPSHOT,
					version:       "4.5.6-SNAPSHOT",
					hash:          "curagt",
					versionedHome: filepath.Join("data", "elastic-agent-4.5.6-SNAPSHOT-curagt"),
				},
				previousAgent: agentInstall{
					parsedVersion: parsed123SNAPSHOT,
					version:       "1.2.3-SNAPSHOT",
					hash:          "prvagt",
					versionedHome: filepath.Join("data", "elastic-agent-1.2.3-SNAPSHOT-prvagt"),
				},
				action:             nil,
				details:            details.NewDetails("4.5.6-SNAPSHOT", details.StateReplacing, ""),
				availableRollbacks: nil,
			},
			wantErr: assert.Error,
		},
		{
			name: "no rollbacks specified in input - no available rollbacks in marker",
			args: args{
				updatedOn: updatedOnNow,
				currentAgent: agentInstall{
					parsedVersion: parsed456SNAPSHOT,
					version:       "4.5.6-SNAPSHOT",
					hash:          "curagt",
					versionedHome: filepath.Join("data", "elastic-agent-4.5.6-SNAPSHOT-curagt"),
				},
				previousAgent: agentInstall{
					parsedVersion: parsed123SNAPSHOT,
					version:       "1.2.3-SNAPSHOT",
					hash:          "prvagt",
					versionedHome: filepath.Join("data", "elastic-agent-1.2.3-SNAPSHOT-prvagt"),
				},
				action:             nil,
				details:            details.NewDetails("4.5.6-SNAPSHOT", details.StateReplacing, ""),
				availableRollbacks: nil,
			},
			wantErr: assert.NoError,
			assertAfterMark: func(t *testing.T, dataDir string) {
				actualMarker, err := LoadMarker(dataDir)
				require.NoError(t, err, "error reading actualMarker content after writing")

				expectedMarker := &UpdateMarker{
					Version:           "4.5.6-SNAPSHOT",
					Hash:              "curagt",
					VersionedHome:     filepath.Join("data", "elastic-agent-4.5.6-SNAPSHOT-curagt"),
					UpdatedOn:         updatedOnNow,
					PrevVersion:       "1.2.3-SNAPSHOT",
					PrevHash:          "prvagt",
					PrevVersionedHome: filepath.Join("data", "elastic-agent-1.2.3-SNAPSHOT-prvagt"),
					Acked:             false,
					Action:            nil,
					Details: &details.Details{
						TargetVersion: "4.5.6-SNAPSHOT",
						State:         "UPG_REPLACING",
						ActionID:      "",
						Metadata:      details.Metadata{},
					},
				}
				assert.Equal(t, expectedMarker, actualMarker)
			},
		},
		{
			name: "available rollbacks passed in - available rollbacks must be present in upgrade marker",
			args: args{
				updatedOn: updatedOnNow,
				currentAgent: agentInstall{
					parsedVersion: parsed920SNAPSHOT,
					version:       "9.2.0-SNAPSHOT",
					hash:          "newagt",
					versionedHome: filepath.Join("data", "elastic-agent-9.2.0-SNAPSHOT-newagt"),
				},
				previousAgent: agentInstall{
					parsedVersion: parsed123SNAPSHOT,
					version:       "1.2.3-SNAPSHOT",
					hash:          "prvagt",
					versionedHome: filepath.Join("data", "elastic-agent-1.2.3-SNAPSHOT-prvagt"),
				},
				action:  nil,
				details: details.NewDetails("9.2.0-SNAPSHOT", details.StateReplacing, ""),
				availableRollbacks: map[string]ttl.TTLMarker{
					filepath.Join("data", "elastic-agent-1.2.3-SNAPSHOT-prvagt"): {
						Version:    "1.2.3-SNAPSHOT",
						ValidUntil: twentyFourHoursFromNow,
					},
				},
			},
			wantErr: assert.NoError,
			assertAfterMark: func(t *testing.T, dataDir string) {
				actualMarker, err := LoadMarker(dataDir)
				require.NoError(t, err, "error reading actualMarker content after writing")

				expectedMarker := &UpdateMarker{
					Version:           "9.2.0-SNAPSHOT",
					Hash:              "newagt",
					VersionedHome:     filepath.Join("data", "elastic-agent-9.2.0-SNAPSHOT-newagt"),
					UpdatedOn:         updatedOnNow,
					PrevVersion:       "1.2.3-SNAPSHOT",
					PrevHash:          "prvagt",
					PrevVersionedHome: filepath.Join("data", "elastic-agent-1.2.3-SNAPSHOT-prvagt"),
					Acked:             false,
					Action:            nil,
					Details: &details.Details{
						TargetVersion: "9.2.0-SNAPSHOT",
						State:         "UPG_REPLACING",
						ActionID:      "",
						Metadata:      details.Metadata{},
					},
					RollbacksAvailable: map[string]ttl.TTLMarker{
						filepath.Join("data", "elastic-agent-1.2.3-SNAPSHOT-prvagt"): {
							Version:    "1.2.3-SNAPSHOT",
							ValidUntil: twentyFourHoursFromNow,
						},
					},
				}
				assert.Equal(t, expectedMarker, actualMarker)
			},
		},
	}

	// use the regular markUpgrade function, disabling the updateActiveCommitFunction that is bundled together
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

			err := markUpgrade(log, dataDir, tc.args.updatedOn, tc.args.currentAgent, tc.args.previousAgent, tc.args.action, tc.args.details, tc.args.availableRollbacks)
			tc.wantErr(t, err)
			if tc.assertAfterMark != nil {
				tc.assertAfterMark(t, dataDir)
			}
		})
	}
}
