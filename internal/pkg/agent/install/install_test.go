// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package install

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/jaypipes/ghw"
	"github.com/jaypipes/ghw/pkg/block"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	v1 "github.com/elastic/elastic-agent/pkg/api/v1"
	"github.com/elastic/elastic-agent/pkg/utils"
)

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

var sampleManifestContent = `
version: co.elastic.agent/v1
kind: PackageManifest
package:
    version: 8.13.0
    snapshot: true
    versioned-home: elastic-agent-fb7370
    path-mappings:
        - data/elastic-agent-fb7370: data/elastic-agent-8.13.0-SNAPSHOT-fb7370
          manifest.yaml: data/elastic-agent-8.13.0-SNAPSHOT-fb7370/manifest.yaml
`

func TestCopyFiles(t *testing.T) {
	type fileType uint

	const (
		REGULAR fileType = iota
		DIRECTORY
		SYMLINK
	)

	type files struct {
		fType   fileType
		path    string
		content []byte
	}

	type testcase struct {
		name          string
		setupFiles    []files
		expectedFiles []files
		mappings      []map[string]string
	}

	testcases := []testcase{
		{
			name: "simple install package mockup",
			setupFiles: []files{
				{fType: REGULAR, path: v1.ManifestFileName, content: []byte(sampleManifestContent)},
				{fType: DIRECTORY, path: filepath.Join("data", "elastic-agent-fb7370"), content: nil},
				{fType: REGULAR, path: filepath.Join("data", "elastic-agent-fb7370", "elastic-agent"), content: []byte("this is an elastic-agent wannabe")},
				{fType: SYMLINK, path: "elastic-agent", content: []byte(filepath.Join("data", "elastic-agent-fb7370", "elastic-agent"))},
			},
			expectedFiles: []files{
				{fType: DIRECTORY, path: filepath.Join("data", "elastic-agent-8.13.0-SNAPSHOT-fb7370"), content: nil},
				{fType: REGULAR, path: filepath.Join("data", "elastic-agent-8.13.0-SNAPSHOT-fb7370", v1.ManifestFileName), content: []byte(sampleManifestContent)},
				{fType: REGULAR, path: filepath.Join("data", "elastic-agent-8.13.0-SNAPSHOT-fb7370", "elastic-agent"), content: []byte("this is an elastic-agent wannabe")},
				{fType: SYMLINK, path: "elastic-agent", content: []byte(filepath.Join("data", "elastic-agent-8.13.0-SNAPSHOT-fb7370", "elastic-agent"))},
			},
			mappings: []map[string]string{
				{
					"data/elastic-agent-fb7370": "data/elastic-agent-8.13.0-SNAPSHOT-fb7370",
					v1.ManifestFileName:         "data/elastic-agent-8.13.0-SNAPSHOT-fb7370/" + v1.ManifestFileName,
				},
			}},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			tmpSrc := t.TempDir()
			tmpDst := t.TempDir()

			for _, sf := range tc.setupFiles {
				switch sf.fType {
				case REGULAR:
					err := os.WriteFile(filepath.Join(tmpSrc, sf.path), sf.content, 0o644)
					require.NoErrorf(t, err, "error writing setup file %s in tempDir %s", sf.path, tmpSrc)

				case DIRECTORY:
					err := os.MkdirAll(filepath.Join(tmpSrc, sf.path), 0o755)
					require.NoErrorf(t, err, "error creating setup directory %s in tempDir %s", sf.path, tmpSrc)

				case SYMLINK:
					err := os.Symlink(string(sf.content), filepath.Join(tmpSrc, sf.path))
					require.NoErrorf(t, err, "error creating symlink %s in tempDir %s", sf.path, tmpSrc)
				}
			}

			// not interested in speed benchmarks, use an arbitrary copyConcurrency value
			copyConcurrency := 4
			err := copyFiles(copyConcurrency, tc.mappings, tmpSrc, tmpDst)
			assert.NoError(t, err)

			for _, ef := range tc.expectedFiles {
				switch ef.fType {
				case REGULAR:
					if assert.FileExistsf(t, filepath.Join(tmpDst, ef.path), "file %s does not exist in output directory %s", ef.path, tmpDst) {
						// check contents
						actualContent, err := os.ReadFile(filepath.Join(tmpDst, ef.path))
						if assert.NoErrorf(t, err, "error reading expected file %s content", ef.path) {
							assert.Equal(t, ef.content, actualContent, "content of expected file %s does not match", ef.path)
						}
					}

				case DIRECTORY:
					assert.DirExistsf(t, filepath.Join(tmpDst, ef.path), "directory %s does not exist in output directory %s", ef.path, tmpDst)

				case SYMLINK:
					actualTarget, err := os.Readlink(filepath.Join(tmpDst, ef.path))
					if assert.NoErrorf(t, err, "error readling expected symlink %s in output dir %s", ef.path, tmpDst) {
						assert.Equal(t, string(ef.content), actualTarget, "unexpected target for symlink %s", ef.path)
					}
				}

			}
		})
	}

}

func TestSetupInstallPath(t *testing.T) {
	tmpdir := t.TempDir()
	ownership, err := utils.CurrentFileOwner()
	require.NoError(t, err)
	err = setupInstallPath(tmpdir, ownership)
	require.NoError(t, err)
	require.FileExists(t, filepath.Join(tmpdir, paths.MarkerFileName))
}
