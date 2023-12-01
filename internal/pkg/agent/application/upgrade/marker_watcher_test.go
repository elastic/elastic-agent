// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package upgrade

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap/zapcore"

	"github.com/stretchr/testify/require"

	"gopkg.in/yaml.v2"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/details"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

func TestMarkerWatcher(t *testing.T) {
	testMarkerDir := t.TempDir()
	testMarkerFile := filepath.Join(testMarkerDir, markerFilename)
	testLogger, _ := logger.NewTesting("watch_marker")

	markerWatcher := newMarkerFileWatcher(testMarkerFile, testLogger)

	testCtx, testCancel := context.WithCancel(context.Background())
	defer testCancel()

	var testDetails *details.Details
	var testDetailsMu sync.Mutex

	var testErr error
	go func() {
		for {
			select {
			case <-testCtx.Done():
				return
			case marker := <-markerWatcher.Watch():
				testDetailsMu.Lock()
				testDetails = marker.Details
				testDetailsMu.Unlock()
			}
		}
	}()

	err := markerWatcher.Run(testCtx)
	require.NoError(t, err)

	// Write out the expected upgrade details to the test upgrade marker
	// file.
	expectedDetails := &details.Details{
		TargetVersion: "8.12.0",
		State:         details.StateWatching,
	}
	marker := updateMarkerSerializer{
		PrevVersion: "8.6.0",
		Details:     expectedDetails,
	}
	data, err := yaml.Marshal(marker)
	require.NoError(t, err)
	err = os.WriteFile(testMarkerFile, data, 0644)
	require.NoError(t, err)

	// We expect that the details that were just written out to the test upgrade
	// marker file will be noticed and read by the watchMarker function, and the
	// testDetailsObs function will be called with them.
	require.Eventually(t, func() bool {
		testDetailsMu.Lock()
		defer testDetailsMu.Unlock()

		return testDetails != nil && testDetails.Equals(expectedDetails)
	}, 1*time.Second, 10*time.Millisecond)

	require.NoError(t, testErr)
}

func TestProcessMarker(t *testing.T) {
	cases := map[string]struct {
		markerFileContents string

		currentAgentVersion string
		currentAgentHash    string

		expectedErrLogMsg bool
		expectedDetails   *details.Details
	}{
		"failed_loading": {
			markerFileContents: `
invalid
`,
			expectedErrLogMsg: true,
			expectedDetails:   nil,
		},
		"no_marker": {
			markerFileContents: "",
			expectedErrLogMsg:  false,
			expectedDetails:    nil,
		},
		"same_version_no_details": {
			markerFileContents: `
prev_version: 8.9.2
`,
			expectedDetails: &details.Details{
				TargetVersion: "unknown",
				State:         details.StateRollback,
			},
		},
		"same_version_with_details_no_state": {
			markerFileContents: `
prev_version: 8.9.2
details:
  target_version: 8.9.2
`,
			expectedErrLogMsg: false,
			expectedDetails: &details.Details{
				TargetVersion: "8.9.2",
				State:         details.StateRollback,
			},
		},
		"same_version_with_details_wrong_state": {
			markerFileContents: `
prev_version: 8.9.2
details:
  target_version: 8.9.2
  state: UPG_WATCHING
`,
			expectedErrLogMsg: false,
			expectedDetails: &details.Details{
				TargetVersion: "8.9.2",
				State:         details.StateRollback,
			},
		},
		"different_version": {
			markerFileContents: `
prev_version: 8.8.2
details:
  target_version: 8.9.2
  state: UPG_WATCHING
`,
			expectedErrLogMsg: false,
			expectedDetails: &details.Details{
				TargetVersion: "8.9.2",
				State:         details.StateWatching,
			},
		},
		"same_version_different_hash": {
			markerFileContents: `
prev_version: 8.9.2
prev_hash: aaaaaa
details:
  target_version: 8.9.2
  state: UPG_WATCHING
`,
			currentAgentVersion: "8.9.2",
			currentAgentHash:    "bbbbbb",
			expectedErrLogMsg:   false,
			expectedDetails: &details.Details{
				TargetVersion: "8.9.2",
				State:         details.StateWatching,
			},
		},
		"same_version_same_hash": {
			markerFileContents: `
prev_version: 8.9.2
prev_hash: aaaaaa
details:
  target_version: 8.9.2
  state: UPG_WATCHING
`,
			currentAgentVersion: "8.9.2",
			currentAgentHash:    "aaaaaa",
			expectedErrLogMsg:   false,
			expectedDetails: &details.Details{
				TargetVersion: "8.9.2",
				State:         details.StateRollback,
			},
		},
		"same_version_same_hash_no_details": {
			markerFileContents: `
prev_version: 8.9.2
prev_hash: aaaaaa
`,
			currentAgentVersion: "8.9.2",
			currentAgentHash:    "aaaaaa",
			expectedErrLogMsg:   false,
			expectedDetails: &details.Details{
				TargetVersion: "unknown",
				State:         details.StateRollback,
			},
		},
	}

	for name, test := range cases {
		t.Run(name, func(t *testing.T) {
			tmpDir := t.TempDir()
			testMarkerFilePath := filepath.Join(tmpDir, markerFilename)
			if test.markerFileContents != "" {
				err := os.WriteFile(testMarkerFilePath, []byte(test.markerFileContents), 0644)
				require.NoError(t, err)
			}
			log, obs := logger.NewTesting("marker_watcher")
			updateCh := make(chan UpdateMarker)
			mfw := MarkerFileWatcher{
				markerFilePath: testMarkerFilePath,
				logger:         log,
				updateCh:       updateCh,
			}

			done := make(chan struct{})
			var markerRead bool
			var actualMarker UpdateMarker
			var markerMu sync.Mutex
			go func() {
				for {
					select {
					case <-done:
						return
					case m := <-updateCh:
						markerMu.Lock()
						markerRead = true
						actualMarker = m
						markerMu.Unlock()
					}
				}
			}()

			// default values for version and hash
			currentVersion := "8.9.2"
			currentCommit := ""

			// apply overrides from testcase
			if test.currentAgentVersion != "" {
				currentVersion = test.currentAgentVersion
			}
			if test.currentAgentHash != "" {
				currentCommit = test.currentAgentHash
			}

			mfw.processMarker(currentVersion, currentCommit)

			// error loading marker
			if test.expectedErrLogMsg {
				done <- struct{}{}
				logs := obs.FilterLevelExact(zapcore.ErrorLevel).TakeAll()
				require.NotEmpty(t, logs)

				markerMu.Lock()
				defer markerMu.Unlock()
				require.False(t, markerRead)

				return
			}

			// no marker
			if test.markerFileContents == "" {
				done <- struct{}{}

				markerMu.Lock()
				defer markerMu.Unlock()
				require.False(t, markerRead)

				return
			}

			// marker exists and can be read
			require.Eventually(t, func() bool {
				markerMu.Lock()
				defer markerMu.Unlock()
				return markerRead
			}, 5*time.Second, 100*time.Millisecond)

			markerMu.Lock()
			defer markerMu.Unlock()

			require.True(t, actualMarker.Details.Equals(test.expectedDetails))
		})

	}
}
