// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package docker

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/pkg/testing/define"
)

func TestContainerName(t *testing.T) {
	tests := []struct {
		batchID string
		want    string
	}{
		{"simple", containerNamePrefix + "simple"},
		{"batch-123", containerNamePrefix + "batch-123"},
		{"batch_abc.def", containerNamePrefix + "batch_abc.def"},
		// Characters outside [a-zA-Z0-9_.-] must be replaced with '-'.
		{"batch/abc:123", containerNamePrefix + "batch-abc-123"},
		{"batch abc", containerNamePrefix + "batch-abc"},
		{"a@b!c", containerNamePrefix + "a-b-c"},
		// Empty string edge case.
		{"", containerNamePrefix},
	}
	for _, tc := range tests {
		t.Run(tc.batchID, func(t *testing.T) {
			assert.Equal(t, tc.want, containerName(tc.batchID))
		})
	}
}

func TestSupported(t *testing.T) {
	p := &provisioner{}

	t.Run("linux ubuntu same arch", func(t *testing.T) {
		assert.True(t, p.Supported(define.OS{
			Type:   define.Linux,
			Distro: Ubuntu,
			Arch:   runtime.GOARCH,
		}))
	})

	t.Run("non-linux rejected", func(t *testing.T) {
		assert.False(t, p.Supported(define.OS{
			Type:   define.Darwin,
			Distro: Ubuntu,
			Arch:   runtime.GOARCH,
		}))
		assert.False(t, p.Supported(define.OS{
			Type:   define.Windows,
			Distro: Ubuntu,
			Arch:   runtime.GOARCH,
		}))
	})

	t.Run("non-ubuntu distro rejected", func(t *testing.T) {
		assert.False(t, p.Supported(define.OS{
			Type:   define.Linux,
			Distro: "rhel",
			Arch:   runtime.GOARCH,
		}))
	})

	t.Run("wrong arch rejected", func(t *testing.T) {
		otherArch := "arm64"
		if runtime.GOARCH == "arm64" {
			otherArch = "amd64"
		}
		assert.False(t, p.Supported(define.OS{
			Type:   define.Linux,
			Distro: Ubuntu,
			Arch:   otherArch,
		}))
	})
}

func TestToolVersions(t *testing.T) {
	t.Run("returns versions for both tools", func(t *testing.T) {
		dir := t.TempDir()
		writeGoMod(t, dir, `module example.com/test

go 1.21

require (
	github.com/magefile/mage v1.15.0
	gotest.tools/gotestsum v1.11.0
)
`)
		got, err := toolVersions(dir)
		require.NoError(t, err)
		assert.Equal(t, "v1.15.0", got.mage)
		assert.Equal(t, "v1.11.0", got.gotestsum)
	})

	t.Run("error when mage is missing", func(t *testing.T) {
		dir := t.TempDir()
		writeGoMod(t, dir, `module example.com/test

go 1.21

require gotest.tools/gotestsum v1.11.0
`)
		_, err := toolVersions(dir)
		require.Error(t, err)
		assert.Contains(t, err.Error(), mageModule)
	})

	t.Run("error when gotestsum is missing", func(t *testing.T) {
		dir := t.TempDir()
		writeGoMod(t, dir, `module example.com/test

go 1.21

require github.com/magefile/mage v1.15.0
`)
		_, err := toolVersions(dir)
		require.Error(t, err)
		assert.Contains(t, err.Error(), gotestsumModule)
	})

	t.Run("error when go.mod does not exist", func(t *testing.T) {
		_, err := toolVersions(t.TempDir())
		require.Error(t, err)
	})

	t.Run("finds tools in repo root go.mod", func(t *testing.T) {
		// The repo's own go.mod pins both tools; navigate from the package directory.
		repoRoot := filepath.Join("..", "..", "..")
		got, err := toolVersions(repoRoot)
		require.NoError(t, err)
		assert.NotEmpty(t, got.mage)
		assert.NotEmpty(t, got.gotestsum)
	})
}

func writeGoMod(t *testing.T, dir, content string) {
	t.Helper()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "go.mod"), []byte(content), 0o644))
}
