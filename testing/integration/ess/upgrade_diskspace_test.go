// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration

package ess

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact/download"
	downloaderrors "github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact/download/errors"
	"github.com/elastic/elastic-agent/internal/pkg/agent/install"
	atesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/testing/integration"
	"github.com/elastic/elastic-agent/testing/upgradetest"
)

const (
	singleFSSize         = 128 * 1024 * 1024 // 128MB
	archiveFSSize        = 64 * 1024 * 1024  // 64MB
	dataFSSize           = 128 * 1024 * 1024 // 128MB
	upgradeExtraDataSize = 50 * 1024 * 1024  // 50MB
	filesystemMargin     = 64 * 1024 * 1024  // 64MB
)

func TestUpgradeCheckDiskSpaceAvailable(t *testing.T) {
	define.Require(t, define.Requirements{
		Group: integration.Upgrade,
		Local: true,
		Sudo:  true,
	})

	fixture, err := atesting.NewFixture(t, upgradetest.EnsureSnapshot(define.Version()), atesting.WithFetcher(atesting.ArtifactFetcher()))
	require.NoError(t, err)
	artifactPath, err := fixture.SrcPackage(t.Context())
	require.NoError(t, err)
	artifactFileName := filepath.Base(artifactPath)
	sourceDirectory := filepath.Dir(artifactPath)
	archiveSize, payloadSize, err := upgrade.GetLocalUpgradeSize("file://" + artifactPath)
	require.NoError(t, err)
	sufficientFSSize := archiveSize + payloadSize + upgradeExtraDataSize + filesystemMargin

	tests := []struct {
		name  string
		setup func(*testing.T) (string, string)
		run   func(*testing.T, error, string, string)
	}{
		{
			name: "sufficient space",
			setup: func(t *testing.T) (string, string) {
				dataFS := makeTestFS(t, sufficientFSSize)
				return dataFS, filepath.Join(dataFS, "downloads")
			},
			run: func(t *testing.T, err error, _, _ string) {
				require.NoError(t, err)
			},
		},
		{
			name: "insufficient space on one filesystem",
			setup: func(t *testing.T) (string, string) {
				dataFS := makeTestFS(t, singleFSSize)
				return dataFS, filepath.Join(dataFS, "downloads")
			},
			run: func(t *testing.T, err error, targetDirectory, _ string) {
				require.Error(t, err)
				require.ErrorContains(t, err, downloaderrors.ErrInsufficientDiskSpace.Error())
				require.Equal(t, 1, strings.Count(err.Error(), "insufficient space at"))
				require.ErrorContains(t, err, targetDirectory)
			},
		},
		{
			name: "insufficient space on split filesystems",
			setup: func(t *testing.T) (string, string) {
				dataFS := makeTestFS(t, dataFSSize)
				archiveFS := makeTestFS(t, archiveFSSize)
				return dataFS, filepath.Join(archiveFS, "downloads")
			},
			run: func(t *testing.T, err error, targetDirectory, dataDirectory string) {
				require.Error(t, err)
				require.ErrorContains(t, err, downloaderrors.ErrInsufficientDiskSpace.Error())
				require.Equal(t, 2, strings.Count(err.Error(), "insufficient space at"))
				require.ErrorContains(t, err, targetDirectory)
				require.ErrorContains(t, err, dataDirectory)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			startFixture, err := define.NewFixtureFromLocalBuild(t, define.Version())
			require.NoError(t, err)
			require.NoError(t, upgradetest.ConfigureFastWatcher(t.Context(), startFixture))
			_, err = startFixture.Install(t.Context(), &atesting.InstallOpts{
				BasePath:       t.TempDir(),
				Force:          true,
				NonInteractive: true,
				Privileged:     true,
			})
			require.NoError(t, err)

			dataDirectory := filepath.Join(startFixture.WorkDir(), "data")
			require.NoError(t, install.StopService(startFixture.WorkDir(), install.DefaultStopTimeout, install.DefaultStopInterval))

			dataFS, targetDirectory := tt.setup(t)

			// Keep the current installation on the default FS. Only the data root and
			// files created for the new version should consume space on the constrained FS.
			currentDataDirectory := dataDirectory + "-current"
			require.NoError(t, os.Rename(dataDirectory, currentDataDirectory))
			require.NoError(t, os.Symlink(dataFS, dataDirectory))
			entries, err := os.ReadDir(currentDataDirectory)
			require.NoError(t, err)
			for _, entry := range entries {
				source := filepath.Join(currentDataDirectory, entry.Name())
				target := filepath.Join(dataFS, entry.Name())
				require.NoError(t, os.Symlink(source, target))
			}

			require.NoError(t, os.MkdirAll(targetDirectory, 0o755))
			watcherConfig := upgradetest.FastWatcherCfg + fmt.Sprintf("\nagent.download:\n  target_directory: '%s'\n", strings.ReplaceAll(targetDirectory, "'", "''"))

			t.Cleanup(func() { require.NoError(t, os.Remove(dataDirectory)) })
			require.NoError(t, install.StartService(startFixture.WorkDir()))

			err = upgradetest.PerformUpgrade(t.Context(), startFixture, fixture, t,
				upgradetest.WithoutInstall(),
				upgradetest.WithSourceURI("file://"+sourceDirectory),
				upgradetest.WithDisableHashCheck(true),
				upgradetest.WithCustomWatcherConfig(watcherConfig))

			tt.run(t, err, targetDirectory, dataDirectory)

			targetPath := filepath.Join(targetDirectory, artifactFileName)
			require.NoFileExists(t, targetPath)
			require.NoFileExists(t, download.AddHashExtension(targetPath))
			require.FileExists(t, filepath.Join(sourceDirectory, artifactFileName))
		})
	}
}
