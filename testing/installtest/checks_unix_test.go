// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build !windows

package installtest

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestValidateFileTreeAllowsExpectedOTelMetricsFilePermissions(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.Chmod(dir, 0o700))
	metricsFile := filepath.Join(dir, otelMetricsFileName)
	require.NoError(t, os.WriteFile(metricsFile, nil, 0o644))

	stat, ok := mustStat(t, metricsFile).Sys().(*syscall.Stat_t)
	require.True(t, ok)
	require.NoError(t, validateFileTree(dir, stat.Uid, stat.Gid))
}

func TestValidateFileTreeRejectsUnexpectedOTelMetricsFilePermissions(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.Chmod(dir, 0o700))
	metricsFile := filepath.Join(dir, otelMetricsFileName)
	require.NoError(t, os.WriteFile(metricsFile, nil, 0o600))

	stat, ok := mustStat(t, metricsFile).Sys().(*syscall.Stat_t)
	require.True(t, ok)
	require.ErrorContains(t, validateFileTree(dir, stat.Uid, stat.Gid), "expected 0644")
}

func mustStat(t *testing.T, path string) os.FileInfo {
	t.Helper()

	info, err := os.Stat(path)
	require.NoError(t, err)
	return info
}
