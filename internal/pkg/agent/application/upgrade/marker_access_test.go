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

func TestWriteMarkerFile(t *testing.T) {
	tmpDir := t.TempDir()
	markerFile := filepath.Join(tmpDir, markerFilename)

	markerBytes := []byte("foo bar")
	err := writeMarkerFile(markerFile, markerBytes, true)
	require.NoError(t, err)

	data, err := os.ReadFile(markerFile)
	require.NoError(t, err)
	require.Equal(t, markerBytes, data)
}
