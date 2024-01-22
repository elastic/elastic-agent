// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package upgrade

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/pkg/core/logger"
)

const foo_component_spec = `
version: 2
inputs:
  - name: foobar
    description: "Foo input"
    platforms:
      - linux/amd64
      - linux/arm64
      - darwin/amd64
      - darwin/arm64
    outputs:
      - elasticsearch
      - kafka
      - logstash
    command:
      args:
        - foo
        - bar
        - baz
`

type fileType uint

const (
	REGULAR fileType = iota
	DIRECTORY
	SYMLINK
)

type files struct {
	fType   fileType
	path    string
	content string
	mode    fs.FileMode
}

func (f files) Name() string {
	return path.Base(f.path)
}

func (f files) Size() int64 {
	return int64(len(f.content))
}

func (f files) Mode() fs.FileMode {
	return f.mode
}

func (f files) ModTime() time.Time {
	return time.Unix(0, 0)
}

func (f files) IsDir() bool {
	return f.fType == DIRECTORY
}

func (f files) Sys() any {
	return nil
}

type createArchiveFunc func(t *testing.T, archiveFiles []files) (string, error)
type checkExtractedPath func(t *testing.T, testDataDir string)

func TestUpgrader_unpack(t *testing.T) {
	type args struct {
		version          string
		archiveGenerator createArchiveFunc
		archiveFiles     []files
	}
	tests := []struct {
		name       string
		args       args
		want       string
		wantErr    assert.ErrorAssertionFunc
		checkFiles checkExtractedPath
	}{
		{
			name: "targz with file before containing folder",
			args: args{
				version: "1.2.3",
				archiveFiles: []files{
					{fType: DIRECTORY, path: "elastic-agent-1.2.3-SNAPSHOT-linux-x86_64", mode: fs.ModeDir | (fs.ModePerm & 0o750)},
					{fType: REGULAR, path: "elastic-agent-1.2.3-SNAPSHOT-linux-x86_64/" + agentCommitFile, content: "abcdefghijklmnopqrstuvwxyz", mode: fs.ModePerm & 0o640},
					{fType: REGULAR, path: "elastic-agent-1.2.3-SNAPSHOT-linux-x86_64/data/elastic-agent-abcdef/package.version", content: "1.2.3", mode: fs.ModePerm & 0o640},
					{fType: DIRECTORY, path: "elastic-agent-1.2.3-SNAPSHOT-linux-x86_64/data", mode: fs.ModeDir | (fs.ModePerm & 0o750)},
					{fType: DIRECTORY, path: "elastic-agent-1.2.3-SNAPSHOT-linux-x86_64/data/elastic-agent-abcdef", mode: fs.ModeDir | (fs.ModePerm & 0o700)},
					{fType: REGULAR, path: "elastic-agent-1.2.3-SNAPSHOT-linux-x86_64/data/elastic-agent-abcdef/" + agentName, content: "Placeholder for the elastic-agent binary", mode: fs.ModePerm & 0o750},
					{fType: DIRECTORY, path: "elastic-agent-1.2.3-SNAPSHOT-linux-x86_64/data/elastic-agent-abcdef/components", mode: fs.ModeDir | (fs.ModePerm & 0o750)},
					{fType: REGULAR, path: "elastic-agent-1.2.3-SNAPSHOT-linux-x86_64/data/elastic-agent-abcdef/components/comp1", content: "Placeholder for component", mode: fs.ModePerm & 0o750},
					{fType: REGULAR, path: "elastic-agent-1.2.3-SNAPSHOT-linux-x86_64/data/elastic-agent-abcdef/components/comp1.spec.yml", content: foo_component_spec, mode: fs.ModePerm & 0o640},
					{fType: SYMLINK, path: "elastic-agent-1.2.3-SNAPSHOT-linux-x86_64/" + agentName, content: "data/elastic-agent-abcdef/" + agentName, mode: fs.ModeSymlink | (fs.ModePerm & 0o750)},
				},
				archiveGenerator: func(t *testing.T, i []files) (string, error) {
					return createTarArchive(t, "elastic-agent-1.2.3-SNAPSHOT-linux-x86_64.tar.gz", i)
				},
			},
			want:    "abcdef",
			wantErr: assert.NoError,
			checkFiles: func(t *testing.T, testDataDir string) {

				versionedHome := filepath.Join(testDataDir, "elastic-agent-abcdef")
				require.DirExists(t, versionedHome, "directory for package.version does not exists")
				stat, err := os.Stat(versionedHome)
				require.NoErrorf(t, err, "error calling Stat() for versionedHome %q", versionedHome)
				expectedPermissions := fs.ModePerm & 0o700
				actualPermissions := fs.ModePerm & stat.Mode()
				assert.Equalf(t, expectedPermissions, actualPermissions, "Wrong permissions set on versioned home %q: expected %O, got %O", versionedHome, expectedPermissions, actualPermissions)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if runtime.GOOS == "windows" {
				t.Skip("tar.gz tests only run on Linux/MacOS")
			}

			testTop := t.TempDir()
			testDataDir := filepath.Join(testTop, "data")
			err := os.MkdirAll(testDataDir, 0o777)
			assert.NoErrorf(t, err, "error creating initial structure %q", testDataDir)
			log, _ := logger.NewTesting(tt.name)
			u := &Upgrader{
				log: log,
			}

			archiveFile, err := tt.args.archiveGenerator(t, tt.args.archiveFiles)
			require.NoError(t, err, "creation of test archive file failed")

			got, err := u.unpack(tt.args.version, archiveFile, testDataDir)
			if !tt.wantErr(t, err, fmt.Sprintf("unpack(%v, %v, %v)", tt.args.version, archiveFile, testDataDir)) {
				return
			}
			assert.Equalf(t, tt.want, got, "unpack(%v, %v, %v)", tt.args.version, archiveFile, testDataDir)
			if tt.checkFiles != nil {
				tt.checkFiles(t, testDataDir)
			}
		})
	}
}

func createTarArchive(t *testing.T, archiveName string, archiveFiles []files) (string, error) {

	outDir := t.TempDir()

	outFilePath := filepath.Join(outDir, archiveName)
	file, err := os.OpenFile(outFilePath, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0o644)
	require.NoErrorf(t, err, "error creating output archive %q", outFilePath)
	defer file.Close()
	zipWriter := gzip.NewWriter(file)
	writer := tar.NewWriter(zipWriter)
	defer func(writer *tar.Writer) {
		err := writer.Close()
		require.NoError(t, err, "error closing tar writer")
		err = zipWriter.Close()
		require.NoError(t, err, "error closing gzip writer")
	}(writer)

	for _, af := range archiveFiles {
		err = addEntryToTarArchive(af, writer)
		require.NoErrorf(t, err, "error adding %q to tar archive", af.path)
	}

	return outFilePath, err
}

func addEntryToTarArchive(af files, writer *tar.Writer) error {
	header, err := tar.FileInfoHeader(&af, af.content)
	if err != nil {
		return err
	}

	header.Name = af.path

	if err := writer.WriteHeader(header); err != nil {
		return err
	}

	if af.IsDir() || af.fType == SYMLINK {
		return nil
	}

	if _, err = io.Copy(writer, strings.NewReader(af.content)); err != nil {
		return fmt.Errorf("copying file %q content: %w", af.path, err)
	}
	return nil
}
