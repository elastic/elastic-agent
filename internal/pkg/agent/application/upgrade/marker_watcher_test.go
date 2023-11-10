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
		Details: expectedDetails,
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
