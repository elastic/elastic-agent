// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package upgradetest

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCheckNoFilesIn(t *testing.T) {
	t.Run("a directory that does not exist has no files", func(t *testing.T) {
		assert.NoError(t, CheckNoFilesIn(filepath.Join(t.TempDir(), "missing")))
	})

	t.Run("directories only", func(t *testing.T) {
		dir := t.TempDir()
		require.NoError(t, os.MkdirAll(filepath.Join(dir, "httpjson", "nested"), 0o755))

		assert.NoError(t, CheckNoFilesIn(dir))
	})

	t.Run("a file in a nested directory is reported", func(t *testing.T) {
		dir := t.TempDir()
		file := filepath.Join(dir, "httpjson", "trace.ndjson")
		require.NoError(t, os.MkdirAll(filepath.Dir(file), 0o755))
		require.NoError(t, os.WriteFile(file, []byte("x"), 0o600))

		err := CheckNoFilesIn(dir)

		require.Error(t, err)
		assert.ErrorContains(t, err, file)
	})
}
