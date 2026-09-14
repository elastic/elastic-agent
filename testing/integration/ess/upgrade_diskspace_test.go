// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration

package ess

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade"
	atesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/testing/integration"
	"github.com/elastic/elastic-agent/testing/upgradetest"
)

const MB = 1024 * 1024
const GB = 1024 * MB

func TestUpgradeCheckDiskSpaceAvailable(t *testing.T) {
	define.Require(t, define.Requirements{
		Group: integration.Upgrade,
		Local: true,
		Sudo:  true,
	})

	fixture, err := atesting.NewFixture(t, upgradetest.EnsureSnapshot(define.Version()), atesting.WithFetcher(atesting.ArtifactFetcher()))
	require.NoError(t, err)
	upgradeArtifactPath, err := fixture.SrcPackage(t.Context())
	require.NoError(t, err)
	sourceDir := filepath.Dir(upgradeArtifactPath)

	archiveSize, decompressedSize, err := upgrade.GetLocalUpgradeSize("file://" + upgradeArtifactPath)
	require.NoError(t, err)

	archiveRequired := archiveSize + upgrade.ChecksumSize
	dataRequired := decompressedSize + upgrade.ExtraDataSize

	// start artifact may not have the same size as the upgrade artifact
	startFixture, err := define.NewFixtureFromLocalBuild(t, define.Version())
	require.NoError(t, err)
	startArtifactPath, err := startFixture.SrcPackage(t.Context())
	require.NoError(t, err)
	_, startDecompressedSize, err := upgrade.GetLocalUpgradeSize("file://" + startArtifactPath)
	require.NoError(t, err)
	startSize := startDecompressedSize + 200*MB

	tests := []struct {
		name  string
		setup func(*testing.T) (string, string)
		run   func(*testing.T, error, string, string)
	}{
		{
			name: "sufficient space on single filesystem",
			setup: func(t *testing.T) (string, string) {
				dataFS := makeTestFS(t, startSize+dataRequired+archiveRequired)
				return dataFS, filepath.Join(dataFS, "downloads")
			},
			run: func(t *testing.T, err error, _, _ string) {
				require.NoError(t, err)
			},
		},
		{
			name: "sufficient space on split filesystems",
			setup: func(t *testing.T) (string, string) {
				dataFS := makeTestFS(t, startSize+dataRequired)
				archiveFS := makeTestFS(t, archiveRequired)
				return dataFS, filepath.Join(archiveFS, "downloads")
			},
			run: func(t *testing.T, err error, _, _ string) {
				require.NoError(t, err)
			},
		},
		{
			name: "insufficient space on single filesystem",
			setup: func(t *testing.T) (string, string) {
				dataFS := makeTestFS(t, startSize)
				return dataFS, filepath.Join(dataFS, "downloads")
			},
			run: func(t *testing.T, err error, targetDir, _ string) {
				require.Error(t, err)
				require.Equal(t, 1, strings.Count(err.Error(), "insufficient disk space for upgrade"))
				require.ErrorContains(t, err, targetDir)
			},
		},
		{
			name: "insufficient space on split filesystems (archive+data)",
			setup: func(t *testing.T) (string, string) {
				dataFS := makeTestFS(t, startSize)
				archiveFS := makeTestFS(t, 128*MB)
				return dataFS, filepath.Join(archiveFS, "downloads")
			},
			run: func(t *testing.T, err error, targetDir, dataDir string) {
				require.Error(t, err)
				require.Equal(t, 2, strings.Count(err.Error(), "insufficient disk space for upgrade"))
				require.ErrorContains(t, err, targetDir)
				require.ErrorContains(t, err, dataDir)
			},
		},
		{
			name: "insufficient space on split filesystems (archive)",
			setup: func(t *testing.T) (string, string) {
				dataFS := makeTestFS(t, startSize+dataRequired)
				archiveFS := makeTestFS(t, 128*MB)
				return dataFS, filepath.Join(archiveFS, "downloads")
			},
			run: func(t *testing.T, err error, targetDir, dataDir string) {
				require.Error(t, err)
				require.Equal(t, 1, strings.Count(err.Error(), "insufficient disk space for upgrade"))
				require.ErrorContains(t, err, targetDir)
			},
		},
		{
			name: "insufficient space on split filesystems (data)",
			setup: func(t *testing.T) (string, string) {
				dataFS := makeTestFS(t, startSize)
				archiveFS := makeTestFS(t, archiveRequired)
				return dataFS, filepath.Join(archiveFS, "downloads")
			},
			run: func(t *testing.T, err error, targetDir, dataDir string) {
				require.Error(t, err)
				require.Equal(t, 1, strings.Count(err.Error(), "insufficient disk space for upgrade"))
				require.ErrorContains(t, err, dataDir)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			startFixture, err := define.NewFixtureFromLocalBuild(t, define.Version())
			require.NoError(t, err)

			dataDir, targetDir := tt.setup(t)

			watcherConfig := upgradetest.FastWatcherCfg + fmt.Sprintf("\nagent.download:\n  target_directory: '%s'\n", strings.ReplaceAll(targetDir, "'", "''"))

			err = upgradetest.PerformUpgrade(t.Context(), startFixture, fixture, t,
				upgradetest.WithBasePath(dataDir),
				upgradetest.WithUnprivileged(false),
				upgradetest.WithSourceURI("file://"+sourceDir),
				upgradetest.WithDisableHashCheck(true),
				upgradetest.WithCustomWatcherConfig(watcherConfig))

			tt.run(t, err, targetDir, dataDir)
		})
	}
}
