// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration

package ess

import (
	"compress/gzip"
	"crypto/rand"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact"
	downloaderrors "github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact/download/errors"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/upgrade/details"
	"github.com/elastic/elastic-agent/testing/integration"
)

const (
	artifactSize      = 80 * 1024 * 1024  // 80MB
	sufficientVolume  = 256 * 1024 * 1024 // 256MB
	singleVolumeSize  = 128 * 1024 * 1024 // 128MB
	archiveVolumeSize = 64 * 1024 * 1024  // 64MB
	dataVolumeSize    = 128 * 1024 * 1024 // 128MB
)

func TestUpgradeDiskSpaceLimit(t *testing.T) {
	define.Require(t, define.Requirements{
		Group: integration.Upgrade,
		Local: true,
		Sudo:  true,
	})

	artifactPath := createTestArtifact(t, artifactSize)

	tests := []struct {
		name  string
		setup func(*testing.T) (string, string)
		run   func(*testing.T, bool, error, string)
	}{
		{
			name: "sufficient space",
			setup: func(t *testing.T) (string, string) {
				dataFS := makeTestFS(t, sufficientVolume)
				return dataFS, filepath.Join(dataFS, "downloads")
			},
			run: func(t *testing.T, hasSpace bool, err error, _ string) {
				require.True(t, hasSpace)
				require.NoError(t, err)
			},
		},
		{
			name: "insufficient space on one filesystem",
			setup: func(t *testing.T) (string, string) {
				dataFS := makeTestFS(t, singleVolumeSize)
				return dataFS, filepath.Join(dataFS, "downloads")
			},
			run: func(t *testing.T, hasSpace bool, err error, targetDirectory string) {
				require.False(t, hasSpace)
				require.ErrorIs(t, err, downloaderrors.ErrInsufficientDiskSpace)
				require.Equal(t, 1, strings.Count(err.Error(), "insufficient space at"))
				require.ErrorContains(t, err, targetDirectory)
			},
		},
		{
			name: "insufficient space on split filesystems",
			setup: func(t *testing.T) (string, string) {
				dataFS := makeTestFS(t, dataVolumeSize)
				archiveFS := makeTestFS(t, archiveVolumeSize)
				return dataFS, filepath.Join(archiveFS, "downloads")
			},
			run: func(t *testing.T, hasSpace bool, err error, targetDirectory string) {
				require.False(t, hasSpace)
				require.ErrorIs(t, err, downloaderrors.ErrInsufficientDiskSpace)
				require.Equal(t, 2, strings.Count(err.Error(), "insufficient space at"))
				require.ErrorContains(t, err, targetDirectory)
				require.ErrorContains(t, err, paths.Data())
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dataFS, targetDirectory := tt.setup(t)
			originalTop := paths.Top()
			paths.SetTop(dataFS)
			t.Cleanup(func() { paths.SetTop(originalTop) })
			require.NoError(t, os.MkdirAll(targetDirectory, 0o755))
			require.NoError(t, os.MkdirAll(paths.Data(), 0o755))

			hasSpace, err := upgrade.CheckDiskSpaceAvailable(t.Context(),
				&artifact.Config{TargetDirectory: targetDirectory},
				details.NewDetails("test", details.StateRequested, ""),
				"file://"+filepath.ToSlash(artifactPath))
			tt.run(t, hasSpace, err, targetDirectory)
		})
	}
}

func createTestArtifact(t *testing.T, size int64) string {
	t.Helper()

	artifactPath := filepath.Join(t.TempDir(), "elastic-agent.tar.gz")
	artifactFile, err := os.Create(artifactPath)
	require.NoError(t, err)

	gzipWriter := gzip.NewWriter(artifactFile)
	_, err = io.CopyN(gzipWriter, rand.Reader, size)
	require.NoError(t, err)
	require.NoError(t, gzipWriter.Close())
	require.NoError(t, artifactFile.Close())

	artifactInfo, err := os.Stat(artifactPath)
	require.NoError(t, err)
	require.Greater(t, artifactInfo.Size(), int64(archiveVolumeSize))
	return artifactPath
}
