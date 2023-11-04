// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package upgrade

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// CreateMarkerTestDir creates a temporary directory that's needed
// for the MarkerFileWatcher to function correctly. This allows tests that
// directly or indirectly use the MarkerFileWatcher to succeed. The
// temporary directory is cleaned up when the test completes.
func CreateMarkerTestDir(t *testing.T) {
	execPath, err := os.Executable()
	require.NoError(t, err)

	testDataDir := filepath.Join(filepath.Dir(execPath), "data")
	err = os.Mkdir(testDataDir, 0755)
	require.NoError(t, err)

	t.Cleanup(func() {
		os.RemoveAll(testDataDir)
	})
}
