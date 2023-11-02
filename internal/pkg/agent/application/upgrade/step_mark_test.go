// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package upgrade

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"gopkg.in/yaml.v2"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/details"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

func TestWatchMarker(t *testing.T) {
	testMarkerDir := t.TempDir()
	testMarkerFile := filepath.Join(testMarkerDir, markerFilename)

	testLogger, _ := logger.NewTesting("watch_marker")

	var testDetails *details.Details
	testDetailsObs := func(upgradeDetails *details.Details) {
		testDetails = upgradeDetails
	}
	testErrChan := make(chan error)
	testCtx, testCancel := context.WithCancel(context.Background())
	defer testCancel()

	var testErr error
	go func() {
		for {
			select {
			case <-testCtx.Done():
				return
			case err := <-testErrChan:
				testErr = err
			}
		}
	}()

	go watchMarker(testCtx, testDetailsObs, testLogger, testErrChan, testMarkerFile)

	expectedDetails := details.Details{
		TargetVersion: "8.12.0",
		State:         details.StateWatching,
	}
	marker := updateMarkerSerializer{
		Details: &expectedDetails,
	}
	data, err := yaml.Marshal(marker)
	require.NoError(t, err)
	err = os.WriteFile(testMarkerFile, data, 0644)
	require.NoError(t, err)

	require.NoError(t, testErr)
	require.NotNil(t, testDetails)
	require.Equal(t, expectedDetails, *testDetails)
}
