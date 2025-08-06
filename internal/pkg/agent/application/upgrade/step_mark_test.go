// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package upgrade

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/details"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi"
	"github.com/elastic/elastic-agent/pkg/core/logger/loggertest"
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

func TestWaitForWatcher(t *testing.T) {
	wantErrWatcherNotStarted := func(t assert.TestingT, err error, i ...interface{}) bool {
		return assert.ErrorIs(t, err, ErrWatcherNotStarted, i)
	}

	tests := []struct {
		name                string
		states              []details.State
		stateChangeInterval time.Duration
		cancelWaitContext   bool
		wantErr             assert.ErrorAssertionFunc
	}{
		{
			name:                "Happy path: watcher is watching already",
			states:              []details.State{details.StateWatching},
			stateChangeInterval: 1 * time.Millisecond,
			wantErr:             assert.NoError,
		},
		{
			name:                "Sad path: watcher is never starting",
			states:              []details.State{details.StateReplacing},
			stateChangeInterval: 1 * time.Millisecond,
			cancelWaitContext:   true,
			wantErr:             wantErrWatcherNotStarted,
		},
		{
			name: "Runaround path: marker is jumping around and landing on watching",
			states: []details.State{
				details.StateRequested,
				details.StateScheduled,
				details.StateDownloading,
				details.StateExtracting,
				details.StateReplacing,
				details.StateRestarting,
				details.StateWatching,
			},
			stateChangeInterval: 1 * time.Millisecond,
			wantErr:             assert.NoError,
		},
		{
			name:                "Timeout: marker is never created",
			states:              nil,
			stateChangeInterval: 1 * time.Millisecond,
			cancelWaitContext:   true,
			wantErr:             wantErrWatcherNotStarted,
		},
		{
			name: "Timeout2: state doesn't get there in time",
			states: []details.State{
				details.StateRequested,
				details.StateScheduled,
				details.StateDownloading,
				details.StateExtracting,
				details.StateReplacing,
				details.StateRestarting,
			},

			stateChangeInterval: 1 * time.Millisecond,
			cancelWaitContext:   true,
			wantErr:             wantErrWatcherNotStarted,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			deadline, ok := t.Deadline()
			if !ok {
				deadline = time.Now().Add(5 * time.Second)
			}
			testCtx, testCancel := context.WithDeadline(context.Background(), deadline)
			defer testCancel()

			tmpDir := t.TempDir()
			updMarkerFilePath := filepath.Join(tmpDir, markerFilename)

			waitContext, waitCancel := context.WithCancel(testCtx)
			defer waitCancel()

			fakeTimeout := 30 * time.Second

			// in order to take timing out of the equation provide a context that we can cancel manually
			// still assert that the parent context and timeout passed are correct
			var createContextFunc createContextWithTimeout = func(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
				assert.Same(t, testCtx, ctx, "parent context should be the same as the waitForWatcherCall")
				assert.Equal(t, fakeTimeout, timeout, "timeout used in new context should be the same as testcase")

				return waitContext, waitCancel
			}

			if len(tt.states) > 0 {
				initialState := tt.states[0]
				writeState(t, updMarkerFilePath, initialState)
			}

			wg := new(sync.WaitGroup)

			var furtherStates []details.State
			if len(tt.states) > 1 {
				// we have more states to produce
				furtherStates = tt.states[1:]
			}

			wg.Add(1)

			// worker goroutine: writes out additional states while the test is blocked on waitOnWatcher() call and expires
			// the wait context if cancelWaitContext is set to true. Timing of the goroutine is driven by stateChangeInterval.
			go func() {
				defer wg.Done()
				tick := time.NewTicker(tt.stateChangeInterval)
				defer tick.Stop()
				for _, state := range furtherStates {
					select {
					case <-testCtx.Done():
						return
					case <-tick.C:
						writeState(t, updMarkerFilePath, state)
					}
				}
				if tt.cancelWaitContext {
					<-tick.C
					waitCancel()
				}
			}()

			log, _ := loggertest.New(tt.name)

			watcher := &upgradeWatcher{}

			tt.wantErr(t, watcher.waitForWatcher(testCtx, log, updMarkerFilePath, fakeTimeout, createContextFunc), fmt.Sprintf("waitForWatcher %s, %v, %s, %s)", updMarkerFilePath, tt.states, tt.stateChangeInterval, fakeTimeout))

			// wait for goroutines to finish
			wg.Wait()
		})
	}
}
