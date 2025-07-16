// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package upgrade

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/details"
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
		DesiredOutcome: OUTCOME_UPGRADE,
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

func TestDesiredOutcome_Serialization(t *testing.T) {
	tempDir := t.TempDir()

	testCases := []struct {
		name           string
		desiredOutcome UpgradeOutcome
		expectError    bool
	}{
		{
			name:           "OUTCOME_UPGRADE",
			desiredOutcome: OUTCOME_UPGRADE,
			expectError:    false,
		},
		{
			name:           "OUTCOME_ROLLBACK",
			desiredOutcome: OUTCOME_ROLLBACK,
			expectError:    false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			markerFile := filepath.Join(tempDir, tc.name+"-marker.yaml")

			// Create marker with specific DesiredOutcome

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
				DesiredOutcome: tc.desiredOutcome,
			}

			// Save the marker
			err := saveMarkerToPath(originalMarker, markerFile, true)
			if tc.expectError {
				require.Error(t, err, "Expected error during save for %s", tc.name)
				return
			}
			require.NoError(t, err, "Failed to save marker for %s", tc.name)

			// Load the marker
			loadedMarker, err := loadMarker(markerFile)
			require.NoError(t, err, "Failed to load marker for %s", tc.name)
			require.NotNil(t, loadedMarker, "loaded marker should not be nil")

			// For valid values, also check they match expected constants
			switch tc.desiredOutcome {
			case OUTCOME_UPGRADE:
				require.Equal(t, OUTCOME_UPGRADE, loadedMarker.DesiredOutcome, "OUTCOME_UPGRADE mismatch")
			case OUTCOME_ROLLBACK:
				require.Equal(t, OUTCOME_ROLLBACK, loadedMarker.DesiredOutcome, "OUTCOME_ROLLBACK mismatch")
			default:
				require.Equal(t, OUTCOME_UPGRADE, loadedMarker.DesiredOutcome,
					"DesiredOutcome not preserved during serialization for %s (expected: %d, got: %d)",
					tc.name, originalMarker.DesiredOutcome, loadedMarker.DesiredOutcome)
			}

			// Clean up
			err = os.Remove(markerFile)
			require.NoError(t, err, "Failed to clean up marker file for %s", tc.name)
		})
	}
}

func TestDesiredOutcome_InvalidYAMLContent(t *testing.T) {
	tempDir := t.TempDir()
	markerFile := filepath.Join(tempDir, "invalid-marker.yaml")

	// Test cases with invalid YAML content for DesiredOutcome
	testCases := []struct {
		name          string
		yamlContent   string
		expectError   bool
		expectedValue UpgradeOutcome
	}{
		{
			name: "Missing value",
			yamlContent: `
version: "8.5.0"
hash: "abc123"
versioned_home: "home/v8.5.0"
updated_on: 2023-01-01T00:00:00Z
`,
			expectError:   false,
			expectedValue: OUTCOME_UPGRADE,
		},
		{
			name: "ProperValue",
			yamlContent: `
version: "8.5.0"
hash: "abc123"
versioned_home: "home/v8.5.0"
updated_on: 2023-01-01T00:00:00Z
desired_outcome: "UPGRADE"
`,
			expectError:   false,
			expectedValue: OUTCOME_UPGRADE,
		},
		{
			name: "RollbackValue",
			yamlContent: `
version: "8.5.0"
hash: "abc123"
versioned_home: "home/v8.5.0"
updated_on: 2023-01-01T00:00:00Z
desired_outcome: "ROLLBACK"
`,
			expectError:   false,
			expectedValue: OUTCOME_ROLLBACK,
		},
		{
			name: "StringValue",
			yamlContent: `
version: "8.5.0"
hash: "abc123"
versioned_home: "home/v8.5.0"
updated_on: 2023-01-01T00:00:00Z
desired_outcome: "invalid_string"
`,
			expectError: true,
		},
		{
			name: "FloatValue",
			yamlContent: `
version: "8.5.0"
hash: "abc123"
versioned_home: "home/v8.5.0"
updated_on: 2023-01-01T00:00:00Z
desired_outcome: 1.5
`,
			expectError: true,
		},
		{
			name: "BooleanValue",
			yamlContent: `
version: "8.5.0"
hash: "abc123"
versioned_home: "home/v8.5.0"
updated_on: 2023-01-01T00:00:00Z
desired_outcome: true
`,
			expectError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Write invalid YAML content to file
			err := os.WriteFile(markerFile, []byte(tc.yamlContent), 0644)
			require.NoError(t, err, "Failed to write test YAML file")

			// Try to load the marker
			marker, err := loadMarker(markerFile)
			if tc.expectError {
				require.Error(t, err, "Expected error when loading invalid YAML for %s", tc.name)
			} else {
				require.NoError(t, err, "Unexpected error when loading YAML for %s", tc.name)
				require.Equal(t, tc.expectedValue, marker.DesiredOutcome)
			}

			// Clean up
			err = os.Remove(markerFile)
			require.NoError(t, err, "Failed to clean up marker file")
		})
	}
}

func TestMarkUpgradeError(t *testing.T) {
	log, _ := loggertest.New("test")
	agent := agentInstall{
		version:       "8.5.0",
		hash:          "abc123",
		versionedHome: "home/v8.5.0",
	}
	previousAgent := agentInstall{
		version:       "8.4.0",
		hash:          "xyz789",
		versionedHome: "home/v8.4.0",
	}
	action := &fleetapi.ActionUpgrade{
		ActionID:   "action-123",
		ActionType: "UPGRADE",
		Data: fleetapi.ActionUpgradeData{
			Version:   "8.5.0",
			SourceURI: "https://example.com/upgrade",
		},
	}
	upgradeDetails := details.NewDetails("8.5.0", details.StateScheduled, "action-123")
	desiredOutcome := OUTCOME_UPGRADE

	testError := errors.New("test error")

	type testCase struct {
		fileName      string
		expectedError error
		markUpgrade   markUpgradeFunc
	}

	testCases := map[string]testCase{
		"should return error if it fails updating the active commit file": {
			fileName:      "commit",
			expectedError: testError,
			markUpgrade: markUpgradeProvider(func(log *logger.Logger, topDirPath, hash string, writeFile writeFileFunc) error {
				return testError
			}, func(name string, data []byte, perm os.FileMode) error {
				return nil
			}),
		},
		"should return error if it fails writing to marker file": {
			fileName:      "marker",
			expectedError: testError,
			markUpgrade: markUpgradeProvider(func(log *logger.Logger, topDirPath, hash string, writeFile writeFileFunc) error {
				return nil
			}, func(name string, data []byte, perm os.FileMode) error {
				return testError
			}),
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			baseDir := t.TempDir()
			paths.SetTop(baseDir)

			err := tc.markUpgrade(log, paths.Data(), time.Now(), agent, previousAgent, action, upgradeDetails, desiredOutcome, 0)
			require.Error(t, err)
			require.ErrorIs(t, err, tc.expectedError)
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

func TestMarkUpgrade(t *testing.T) {
	var parsed123SNAPSHOT = agtversion.NewParsedSemVer(1, 2, 3, "SNAPSHOT", "")
	var parsed456SNAPSHOT = agtversion.NewParsedSemVer(4, 5, 6, "SNAPSHOT", "")

	// fix a timestamp (truncated to the second because of loss of precision during marshalling/unmarshalling)
	updatedOnNow := time.Now().UTC().Truncate(time.Second)

	type args struct {
		updatedOn      time.Time
		currentAgent   agentInstall
		previousAgent  agentInstall
		action         *fleetapi.ActionUpgrade
		details        *details.Details
		desiredOutcome UpgradeOutcome
		rollbackWindow time.Duration
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
				action:         nil,
				details:        details.NewDetails("4.5.6-SNAPSHOT", details.StateReplacing, ""),
				desiredOutcome: OUTCOME_UPGRADE,
				rollbackWindow: 0,
			},
			wantErr: assert.Error,
		},
		{
			name: "no rollback window specified - no available rollbacks",
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
				action:         nil,
				details:        details.NewDetails("4.5.6-SNAPSHOT", details.StateReplacing, ""),
				desiredOutcome: OUTCOME_UPGRADE,
				rollbackWindow: 0,
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
					DesiredOutcome: OUTCOME_UPGRADE,
				}
				assert.Equal(t, expectedMarker, actualMarker)
			},
		},
		{
			name: "rollback window specified - available rollbacks must be present",
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
				action:         nil,
				details:        details.NewDetails("4.5.6-SNAPSHOT", details.StateReplacing, ""),
				desiredOutcome: OUTCOME_UPGRADE,
				rollbackWindow: 7 * 24 * time.Hour,
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
						Metadata: details.Metadata{
							RollbacksAvailable: []details.RollbackAvailable{
								{
									Version:    "1.2.3-SNAPSHOT",
									Home:       filepath.Join("data", "elastic-agent-1.2.3-SNAPSHOT-prvagt"),
									ValidUntil: updatedOnNow.Add(7 * 24 * time.Hour),
								},
							},
						},
					},
					DesiredOutcome: OUTCOME_UPGRADE,
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

			err := markUpgrade(log, dataDir, tc.args.updatedOn, tc.args.currentAgent, tc.args.previousAgent, tc.args.action, tc.args.details, tc.args.desiredOutcome, tc.args.rollbackWindow)
			tc.wantErr(t, err)
			if tc.assertAfterMark != nil {
				tc.assertAfterMark(t, dataDir)
			}
		})
	}
}
