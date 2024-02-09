// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package install

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/jaypipes/ghw"
	"github.com/jaypipes/ghw/pkg/block"
	"github.com/schollz/progressbar/v3"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/cli"
	"github.com/elastic/elastic-agent/pkg/utils"
)

func TestWrapper(t *testing.T) {
	topPath := t.TempDir()
	wrapperPath := t.TempDir()
	esPath := filepath.Join(wrapperPath, "elastic-agent")
	err := placeShellWrapper(topPath, esPath)
	require.NoError(t, err)

	res, err := os.ReadFile(esPath)
	require.NoError(t, err)
	expected := strings.Replace(paths.ShellWrapper, "%s", topPath, -1)
	require.Equal(t, expected, string(res))
}

func TestPreInstall(t *testing.T) {
	pt := progressbar.DefaultSilent(0)
	topPath := t.TempDir()

	exe, err := os.Executable()
	require.NoError(t, err)
	t.Logf("got: %s", exe)

	base := filepath.Dir(exe)

	//fakeout path verification in setupInstall()
	name := "elastic-agent"
	if runtime.GOOS == "windows" {
		name = "elastic-agent.exe"
	}
	_, err = os.Create(filepath.Join(base, name))
	require.NoError(t, err)

	sourceDir, err := setupInstall(pt, topPath, "", logp.L())
	require.NoError(t, err)
	require.Equal(t, base, sourceDir)
}

func TestFileCopy(t *testing.T) {
	inputDir := t.TempDir()
	outputDir := t.TempDir()
	// create some example files
	_, err := os.Create(filepath.Join(inputDir, "elastic-agent"))
	require.NoError(t, err)
	pt := progressbar.DefaultSilent(0)

	err = copyFiles(pt, outputDir, cli.NewIOStreams(), inputDir, utils.CurrentFileOwner())
	require.NoError(t, err)

	require.FileExists(t, filepath.Join(outputDir, "elastic-agent"))
	require.FileExists(t, filepath.Join(outputDir, paths.MarkerFileName))
}

func TestHasAllSSDs(t *testing.T) {
	cases := map[string]struct {
		block    ghw.BlockInfo
		expected bool
	}{
		"no_ssds": {
			block: ghw.BlockInfo{Disks: []*block.Disk{
				{DriveType: ghw.DRIVE_TYPE_HDD},
				{DriveType: ghw.DRIVE_TYPE_ODD},
				{DriveType: ghw.DRIVE_TYPE_FDD},
			}},
			expected: false,
		},
		"some_ssds": {
			block: ghw.BlockInfo{Disks: []*block.Disk{
				{DriveType: ghw.DRIVE_TYPE_SSD},
				{DriveType: ghw.DRIVE_TYPE_HDD},
				{DriveType: ghw.DRIVE_TYPE_ODD},
				{DriveType: ghw.DRIVE_TYPE_FDD},
			}},
			expected: false,
		},
		"all_ssds": {
			block: ghw.BlockInfo{Disks: []*block.Disk{
				{DriveType: ghw.DRIVE_TYPE_SSD},
				{DriveType: ghw.DRIVE_TYPE_SSD},
				{DriveType: ghw.DRIVE_TYPE_SSD},
			}},
			expected: true,
		},
		"unknown": {
			block: ghw.BlockInfo{Disks: []*block.Disk{
				{DriveType: ghw.DRIVE_TYPE_UNKNOWN},
			}},
			expected: false,
		},
	}

	for name, test := range cases {
		t.Run(name, func(t *testing.T) {
			actual := hasAllSSDs(test.block)
			require.Equal(t, test.expected, actual)
		})
	}
}
