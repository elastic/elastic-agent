// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package upgrade

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/details"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi"
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

func Test_markUpgradeLocking(t *testing.T) {

	type dataDirHookFunc func(t *testing.T, dataDir string)

	type args struct {
		agent          agentInstall
		previousAgent  agentInstall
		action         *fleetapi.ActionUpgrade
		upgradeDetails *details.Details
		desiredOutcome UpgradeOutcome
	}

	newAgent456 := agentInstall{
		parsedVersion: agtversion.NewParsedSemVer(4, 5, 6, "", ""),
		version:       "4.5.6",
		hash:          "newagt",
		versionedHome: "elastic-agent-4.5.6-newagt",
	}

	prevAgent123 := agentInstall{
		parsedVersion: agtversion.NewParsedSemVer(1, 2, 3, "", ""),
		version:       "1.2.3",
		hash:          "oldagt",
		versionedHome: "elastic-agent-1.2.3-oldagt",
	}

	tests := []struct {
		name                       string
		args                       args
		beforeUpdateMarkerCreation dataDirHookFunc
		afterUpdateMarkerCreation  dataDirHookFunc
		wantErr                    assert.ErrorAssertionFunc
	}{
		{
			name: "Lock file is created when writing update marker",
			args: args{
				agent:          newAgent456,
				previousAgent:  prevAgent123,
				action:         nil,
				upgradeDetails: nil,
			},
			afterUpdateMarkerCreation: func(t *testing.T, dataDir string) {
				assert.FileExists(t, markerFilePath(dataDir), "Update marker file must exist")
				assert.FileExists(t, markerFilePath(dataDir)+".lock", "Update marker lock file must exist")
				// verify we managed to write the actual update marker
				updateMarker, err := LoadMarker(dataDir)
				require.NoError(t, err, "loading update marker should not fail")
				checkUpgradeMarker(t, updateMarker, prevAgent123, newAgent456)
			},
			wantErr: assert.NoError,
		},
		{
			name: "Update marker is re-lockable after writing",
			args: args{
				agent:          newAgent456,
				previousAgent:  prevAgent123,
				action:         nil,
				upgradeDetails: nil,
			},
			afterUpdateMarkerCreation: func(t *testing.T, dataDir string) {
				assert.FileExists(t, markerFilePath(dataDir), "Update marker file must exist")
				assert.FileExists(t, markerFilePath(dataDir)+".lock", "Update marker lock file must exist")
				fileLock, err := lockMarkerFile(markerFilePath(dataDir))
				require.NoError(t, err, "re-locking update marker after initial write should not fail")
				t.Cleanup(func() {
					errUnlock := fileLock.Unlock()
					assert.NoError(t, errUnlock, "re-unlocking update marker file should not fail")
				})
			},
			wantErr: assert.NoError,
		},
		{
			name: "Update marker creation fails if marker is already locked by the same process",
			args: args{
				agent:          newAgent456,
				previousAgent:  prevAgent123,
				action:         nil,
				upgradeDetails: nil,
			},
			beforeUpdateMarkerCreation: func(t *testing.T, dataDir string) {
				// write some fake data in update marker file
				updateMarkerFilePath := markerFilePath(dataDir)
				err := os.WriteFile(updateMarkerFilePath, []byte("this: is not a real update marker"), 0o664)
				require.NoError(t, err, "error creating fake update marker")

				// lock the fake update marker
				fileLock, err := lockMarkerFile(updateMarkerFilePath)
				require.NoError(t, err, "locking fake update marker should not fail")

				t.Cleanup(func() {
					errUnlock := fileLock.Unlock()
					assert.NoError(t, errUnlock, "unlocking fake update marker should not fail")
				})
			},
			afterUpdateMarkerCreation: func(t *testing.T, dataDir string) {
				// verify we managed to write the actual update marker
				_, err := LoadMarker(dataDir)
				assert.Error(t, err, "loading update marker should fail")
			},
			wantErr: assert.Error,
		},
		{
			name: "Update marker creation should fail if marker is already locked by another process", args: args{
			agent:          newAgent456,
			previousAgent:  prevAgent123,
			action:         nil,
			upgradeDetails: nil,
		},
			beforeUpdateMarkerCreation: func(t *testing.T, dataDir string) {
				// write some fake data in update marker file
				updateMarkerFilePath := markerFilePath(dataDir)
				err := os.WriteFile(updateMarkerFilePath, []byte("this: is not a real update marker"), 0o664)
				require.NoError(t, err, "error creating fake update marker")

				// lock the fake update marker using an external process
				lockFilePath := updateMarkerFilePath + ".lock"
				cmdCancel, lockFileCmd := createFileLockerCmd(t, lockFilePath)

				fileLockerStdErr, err := lockFileCmd.StderrPipe()
				require.NoError(t, err, "Error getting stderr pipe from filelocker")

				fileLockedCh := make(chan struct{})

				// consume stderr to check for locking
				go func() {
					scanner := bufio.NewScanner(fileLockerStdErr)
					for scanner.Scan() {
						line := scanner.Text()
						if strings.Contains(line, "Acquired lock on file") {
							fileLockedCh <- struct{}{}
						}
					}
				}()

				err = lockFileCmd.Start()
				require.NoError(t, err, "running filelocker should not fail")

				t.Cleanup(func() {
					cmdCancel()
					_ = lockFileCmd.Wait()
				})

				select {
				case <-fileLockedCh:
					// file was locked from the external process: all good
					t.Log("external filelocker acquired the lock!")
				case <-time.After(30 * time.Second):
					t.Fatalf("timed out waiting for file locker to lock the file")
				}
			},
			afterUpdateMarkerCreation: func(t *testing.T, dataDir string) {
				// verify we can't read the actual update marker since it's still locked
				_, err := LoadMarker(dataDir)
				require.Error(t, err, "loading update marker should fail")
			},
			wantErr: assert.Error,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDataDir := t.TempDir()
			logger, _ := loggertest.New(t.Name())
			if tt.beforeUpdateMarkerCreation != nil {
				tt.beforeUpdateMarkerCreation(t, tmpDataDir)
			}
			tt.wantErr(t, markUpgrade(logger, tmpDataDir, tt.args.agent, tt.args.previousAgent, tt.args.action, tt.args.upgradeDetails, tt.args.desiredOutcome), fmt.Sprintf("markUpgrade(%v, %v, %v, %v, %v, %v, %v)", logger, tmpDataDir, tt.args.agent, tt.args.previousAgent, tt.args.action, tt.args.upgradeDetails, tt.args.desiredOutcome))
			if tt.afterUpdateMarkerCreation != nil {
				tt.afterUpdateMarkerCreation(t, tmpDataDir)
			}
		})
	}
}

func createFileLockerCmd(t *testing.T, lockFilePath string) (context.CancelFunc, *exec.Cmd) {
	executableName := "filelocker"
	if runtime.GOOS == "windows" {
		executableName += ".exe"
	}
	filelockerExecutablePath := filepath.Join("test", "filelocker", executableName)
	require.FileExistsf(
		t,
		filelockerExecutablePath,
		"filelocker executable %s should exist. Please ensure that mage build:testbinaries has been executed.",
		filelockerExecutablePath,
	)

	cmdCtx, cmdCancel := context.WithCancel(t.Context())
	lockFileCmd := exec.CommandContext(cmdCtx, filelockerExecutablePath, "-lockfile", lockFilePath)
	return cmdCancel, lockFileCmd
}

func checkUpgradeMarker(t *testing.T, updateMarker *UpdateMarker, prevAgent agentInstall, newAgent agentInstall) {
	t.Helper()
	require.NotNil(t, updateMarker, "update marker should not be nil")

	// Previous version assertions
	assert.Equal(t, updateMarker.PrevVersion, prevAgent.version, "Previous agent version mismatch")
	assert.Equal(t, updateMarker.PrevVersionedHome, prevAgent.versionedHome, "Previous agent versionedHome mismatch")
	assert.Equal(t, updateMarker.PrevHash, prevAgent.hash, "Previous agent hash mismatch")

	// New version assertions
	assert.Equal(t, updateMarker.Version, newAgent.version, "New agent version mismatch")
	assert.Equal(t, updateMarker.VersionedHome, newAgent.versionedHome, "New agent versionedHome mismatch")
	assert.Equal(t, updateMarker.Hash, newAgent.hash, "New agent hash mismatch")

	// Check that there is an updated timestamp
	assert.NotZero(t, updateMarker.UpdatedOn, "updated on timestamp should not be zero")
}
