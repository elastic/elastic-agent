// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package diagnostics

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
)

func TestZipLogs(t *testing.T) {
	// Setup a directory structure of: logs/httpjson/log.ndjson
	{
		paths.SetTop(t.TempDir())
		dir := filepath.Join(paths.Home(), "logs/sub-dir")
		require.NoError(t, os.MkdirAll(dir, 0o700))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "log.ndjson"), []byte(".\n"), 0o600))
	}

	// Zip the logs directory.
	buf := new(bytes.Buffer)
	w := zip.NewWriter(buf)
	require.NoError(t, zipLogs(w, time.Now()))
	require.NoError(t, w.Close())

	type zippedItem struct {
		Name  string
		IsDir bool
	}

	// Read back the contents.
	r, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	require.NoError(t, err)
	var observed []zippedItem
	for _, f := range r.File {
		observed = append(observed, zippedItem{Name: f.Name, IsDir: f.FileInfo().IsDir()})
	}

	// Verify the results.
	expected := []zippedItem{
		{"logs/", true},
		{"logs/elastic-agent-unknow/sub-dir/", true},
		{"logs/elastic-agent-unknow/sub-dir/log.ndjson", false},
	}
	assert.Equal(t, expected, observed)
}
