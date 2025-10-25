// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package upgrade

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"errors"
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

	v1 "github.com/elastic/elastic-agent/pkg/api/v1"
	"github.com/elastic/elastic-agent/pkg/core/logger"
	"github.com/elastic/elastic-agent/pkg/core/logger/loggertest"
)

const agentBinaryPlaceholderContent = "Placeholder for the elastic-agent binary"

const ea_123_manifest = `
version: co.elastic.agent/v1
kind: PackageManifest
package:
  version: 1.2.3
  snapshot: true
  versioned-home: data/elastic-agent-abcdef
  flavors:
    basic:
      - comp1
      - comp2
    servers:
      - comp1
      - comp2
      - comp3
  path-mappings:
    - data/elastic-agent-abcdef: data/elastic-agent-1.2.3-SNAPSHOT-abcdef
      manifest.yaml: data/elastic-agent-1.2.3-SNAPSHOT-abcdef/manifest.yaml
`
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

const foo_component_spec_with_dirs = `
component_files:
 - component_dir/*
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
const foo_component_spec_with_archive = `
component_files:
 - component.zip
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

var archiveFilesWithMoreComponents = []files{
	{fType: DIRECTORY, path: "elastic-agent-1.2.3-SNAPSHOT-someos-x86_64", mode: fs.ModeDir | (fs.ModePerm & 0o750)},
	{fType: REGULAR, path: "elastic-agent-1.2.3-SNAPSHOT-someos-x86_64/" + v1.ManifestFileName, content: ea_123_manifest, mode: fs.ModePerm & 0o640},
	{fType: REGULAR, path: "elastic-agent-1.2.3-SNAPSHOT-someos-x86_64/" + agentCommitFile, content: "abcdefghijklmnopqrstuvwxyz", mode: fs.ModePerm & 0o640},
	{fType: DIRECTORY, path: "elastic-agent-1.2.3-SNAPSHOT-someos-x86_64/data", mode: fs.ModeDir | (fs.ModePerm & 0o750)},
	{fType: DIRECTORY, path: "elastic-agent-1.2.3-SNAPSHOT-someos-x86_64/data/elastic-agent-abcdef", mode: fs.ModeDir | (fs.ModePerm & 0o750)},
	{fType: REGULAR, path: "elastic-agent-1.2.3-SNAPSHOT-someos-x86_64/data/elastic-agent-abcdef/" + AgentName, content: agentBinaryPlaceholderContent, mode: fs.ModePerm & 0o750},
	{fType: REGULAR, path: "elastic-agent-1.2.3-SNAPSHOT-someos-x86_64/data/elastic-agent-abcdef/package.version", content: "1.2.3", mode: fs.ModePerm & 0o640},
	{fType: DIRECTORY, path: "elastic-agent-1.2.3-SNAPSHOT-someos-x86_64/data/elastic-agent-abcdef/components", mode: fs.ModeDir | (fs.ModePerm & 0o750)},
	{fType: REGULAR, path: "elastic-agent-1.2.3-SNAPSHOT-someos-x86_64/data/elastic-agent-abcdef/components/comp1", binary: true, content: "Placeholder for component", mode: fs.ModePerm & 0o750},
	{fType: REGULAR, path: "elastic-agent-1.2.3-SNAPSHOT-someos-x86_64/data/elastic-agent-abcdef/components/comp1", content: "Placeholder for component", mode: fs.ModePerm & 0o750},
	{fType: REGULAR, path: "elastic-agent-1.2.3-SNAPSHOT-someos-x86_64/data/elastic-agent-abcdef/components/comp1.spec.yml", content: foo_component_spec, mode: fs.ModePerm & 0o640},
	{fType: REGULAR, path: "elastic-agent-1.2.3-SNAPSHOT-someos-x86_64/data/elastic-agent-abcdef/components/comp2", binary: true, content: "Placeholder for component", mode: fs.ModePerm & 0o750},
	{fType: REGULAR, path: "elastic-agent-1.2.3-SNAPSHOT-someos-x86_64/data/elastic-agent-abcdef/components/comp2.spec.yml", content: foo_component_spec_with_dirs, mode: fs.ModePerm & 0o640},
	{fType: REGULAR, path: "elastic-agent-1.2.3-SNAPSHOT-someos-x86_64/data/elastic-agent-abcdef/components/comp3", binary: true, content: "Placeholder for component", mode: fs.ModePerm & 0o750},
	{fType: REGULAR, path: "elastic-agent-1.2.3-SNAPSHOT-someos-x86_64/data/elastic-agent-abcdef/components/comp3.spec.yml", content: foo_component_spec_with_archive, mode: fs.ModePerm & 0o640},
	{fType: REGULAR, path: "elastic-agent-1.2.3-SNAPSHOT-someos-x86_64/data/elastic-agent-abcdef/components/component.zip", content: "inner file content", mode: fs.ModePerm & 0o640},
	{fType: DIRECTORY, path: "elastic-agent-1.2.3-SNAPSHOT-someos-x86_64/data/elastic-agent-abcdef/components/component_dir", mode: fs.ModeDir | (fs.ModePerm & 0o750)},
	{fType: REGULAR, path: "elastic-agent-1.2.3-SNAPSHOT-someos-x86_64/data/elastic-agent-abcdef/components/component_dir/inner_file", content: "inner file content", mode: fs.ModePerm & 0o640},
}

var archiveFilesWithManifestNoSymlink = []files{
	{fType: DIRECTORY, path: "elastic-agent-1.2.3-SNAPSHOT-someos-x86_64", mode: fs.ModeDir | (fs.ModePerm & 0o750)},
	{fType: REGULAR, path: "elastic-agent-1.2.3-SNAPSHOT-someos-x86_64/" + v1.ManifestFileName, content: ea_123_manifest, mode: fs.ModePerm & 0o640},
	{fType: REGULAR, path: "elastic-agent-1.2.3-SNAPSHOT-someos-x86_64/" + agentCommitFile, content: "abcdefghijklmnopqrstuvwxyz", mode: fs.ModePerm & 0o640},
	{fType: DIRECTORY, path: "elastic-agent-1.2.3-SNAPSHOT-someos-x86_64/data", mode: fs.ModeDir | (fs.ModePerm & 0o750)},
	{fType: DIRECTORY, path: "elastic-agent-1.2.3-SNAPSHOT-someos-x86_64/data/elastic-agent-abcdef", mode: fs.ModeDir | (fs.ModePerm & 0o750)},
	{fType: REGULAR, path: "elastic-agent-1.2.3-SNAPSHOT-someos-x86_64/data/elastic-agent-abcdef/" + AgentName, content: agentBinaryPlaceholderContent, mode: fs.ModePerm & 0o750},
	{fType: REGULAR, path: "elastic-agent-1.2.3-SNAPSHOT-someos-x86_64/data/elastic-agent-abcdef/package.version", content: "1.2.3", mode: fs.ModePerm & 0o640},
	{fType: DIRECTORY, path: "elastic-agent-1.2.3-SNAPSHOT-someos-x86_64/data/elastic-agent-abcdef/components", mode: fs.ModeDir | (fs.ModePerm & 0o750)},
	{fType: REGULAR, path: "elastic-agent-1.2.3-SNAPSHOT-someos-x86_64/data/elastic-agent-abcdef/components/comp1", content: "Placeholder for component", mode: fs.ModePerm & 0o750},
	{fType: REGULAR, path: "elastic-agent-1.2.3-SNAPSHOT-someos-x86_64/data/elastic-agent-abcdef/components/comp1.spec.yml", content: foo_component_spec, mode: fs.ModePerm & 0o640},
}

var outOfOrderArchiveFilesNoManifestNoSymlink = []files{
	{fType: DIRECTORY, path: "elastic-agent-1.2.3-SNAPSHOT-someos-x86_64", mode: fs.ModeDir | (fs.ModePerm & 0o750)},
	{fType: REGULAR, path: "elastic-agent-1.2.3-SNAPSHOT-someos-x86_64/" + agentCommitFile, content: "abcdefghijklmnopqrstuvwxyz", mode: fs.ModePerm & 0o640},
	{fType: REGULAR, path: "elastic-agent-1.2.3-SNAPSHOT-someos-x86_64/data/elastic-agent-abcdef/package.version", content: "1.2.3", mode: fs.ModePerm & 0o640},
	{fType: REGULAR, path: "elastic-agent-1.2.3-SNAPSHOT-someos-x86_64/data/elastic-agent-abcdef/" + AgentName, content: agentBinaryPlaceholderContent, mode: fs.ModePerm & 0o750},
	{fType: DIRECTORY, path: "elastic-agent-1.2.3-SNAPSHOT-someos-x86_64/data", mode: fs.ModeDir | (fs.ModePerm & 0o750)},
	{fType: DIRECTORY, path: "elastic-agent-1.2.3-SNAPSHOT-someos-x86_64/data/elastic-agent-abcdef", mode: fs.ModeDir | (fs.ModePerm & 0o700)},
	{fType: DIRECTORY, path: "elastic-agent-1.2.3-SNAPSHOT-someos-x86_64/data/elastic-agent-abcdef/components", mode: fs.ModeDir | (fs.ModePerm & 0o750)},
	{fType: REGULAR, path: "elastic-agent-1.2.3-SNAPSHOT-someos-x86_64/data/elastic-agent-abcdef/components/comp1", content: "Placeholder for component", mode: fs.ModePerm & 0o750},
	{fType: REGULAR, path: "elastic-agent-1.2.3-SNAPSHOT-someos-x86_64/data/elastic-agent-abcdef/components/comp1.spec.yml", content: foo_component_spec, mode: fs.ModePerm & 0o640},
}

var agentArchiveSymLink = files{fType: SYMLINK, path: "elastic-agent-1.2.3-SNAPSHOT-someos-x86_64/" + AgentName, content: "data/elastic-agent-abcdef/" + AgentName, mode: fs.ModeSymlink | (fs.ModePerm & 0o750)}

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
	binary  bool
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

func TestUpgrader_unpackTarGz(t *testing.T) {
	testError := errors.New("test error")
	type args struct {
		version          string
		archiveGenerator createArchiveFunc
		archiveFiles     []files
	}

	binarySuffix := ""
	if runtime.GOOS == "windows" {
		binarySuffix = ".exe"
	}

	tests := []struct {
		name          string
		args          args
		want          UnpackResult
		expectedError error
		checkFiles    checkExtractedPath
		flavor        string
		copy          copyFunc
		mkdirAll      mkdirAllFunc
		openFile      openFileFunc
	}{
		{
			name: "file before containing folder",
			args: args{
				version:      "1.2.3",
				archiveFiles: append(outOfOrderArchiveFilesNoManifestNoSymlink, agentArchiveSymLink),
				archiveGenerator: func(t *testing.T, i []files) (string, error) {
					return createTarArchive(t, "elastic-agent-1.2.3-SNAPSHOT-someos-x86_64.tar.gz", i)
				},
			},
			want: UnpackResult{
				Hash:          "abcdef",
				VersionedHome: filepath.Join("data", "elastic-agent-abcdef"),
			},
			expectedError: nil,
			checkFiles: func(t *testing.T, testDataDir string) {
				versionedHome := filepath.Join(testDataDir, "elastic-agent-abcdef")
				checkExtractedFilesOutOfOrder(t, versionedHome)
			},
			copy:     io.Copy,
			mkdirAll: os.MkdirAll,
			openFile: os.OpenFile,
		},
		{
			name: "package with manifest file",
			args: args{
				version:      "1.2.3",
				archiveFiles: append(archiveFilesWithManifestNoSymlink, agentArchiveSymLink),
				archiveGenerator: func(t *testing.T, i []files) (string, error) {
					return createTarArchive(t, "elastic-agent-1.2.3-SNAPSHOT-someos-x86_64.tar.gz", i)
				},
			},
			want: UnpackResult{
				Hash:          "abcdef",
				VersionedHome: filepath.Join("data", "elastic-agent-1.2.3-SNAPSHOT-abcdef"),
			},
			expectedError: nil,
			checkFiles:    checkExtractedFilesWithManifest,
			copy:          io.Copy,
			mkdirAll:      os.MkdirAll,
			openFile:      os.OpenFile,
		},
		{
			name: "package with basic flavor",
			args: args{
				version:      "1.2.3",
				archiveFiles: append(archiveFilesWithMoreComponents, agentArchiveSymLink),
				archiveGenerator: func(t *testing.T, i []files) (string, error) {
					return createTarArchive(t, "elastic-agent-1.2.3-SNAPSHOT-someos-x86_64.tar.gz", i)
				},
			},
			want: UnpackResult{
				Hash:          "abcdef",
				VersionedHome: filepath.Join("data", "elastic-agent-1.2.3-SNAPSHOT-abcdef"),
			},
			expectedError: nil,
			flavor:        "basic",
			checkFiles: func(t *testing.T, testDataDir string) {
				checkFilesPresence(t, testDataDir,
					[]string{
						filepath.Join("components", "comp1"+binarySuffix), filepath.Join("components", "comp1.spec.yml"),
						filepath.Join("components", "comp2"+binarySuffix), filepath.Join("components", "comp2.spec.yml"),
						filepath.Join("components", "component_dir", "inner_file"),
					},
					[]string{filepath.Join("components", "comp3"), filepath.Join("components", "comp3.spec.yml"), filepath.Join("components", "component.zip")})
			},
			copy:     io.Copy,
			mkdirAll: os.MkdirAll,
			openFile: os.OpenFile,
		},
		{
			name: "package with servers flavor",
			args: args{
				version:      "1.2.3",
				archiveFiles: append(archiveFilesWithMoreComponents, agentArchiveSymLink),
				archiveGenerator: func(t *testing.T, i []files) (string, error) {
					return createTarArchive(t, "elastic-agent-1.2.3-SNAPSHOT-someos-x86_64.tar.gz", i)
				},
			},
			want: UnpackResult{
				Hash:          "abcdef",
				VersionedHome: filepath.Join("data", "elastic-agent-1.2.3-SNAPSHOT-abcdef"),
			},
			expectedError: nil,
			flavor:        "servers",
			checkFiles: func(t *testing.T, testDataDir string) {
				checkFilesPresence(t, testDataDir,
					[]string{
						filepath.Join("components", "comp1"+binarySuffix), filepath.Join("components", "comp1.spec.yml"),
						filepath.Join("components", "comp2"+binarySuffix), filepath.Join("components", "comp2.spec.yml"),
						filepath.Join("components", "component_dir", "inner_file"),
						filepath.Join("components", "comp3"+binarySuffix), filepath.Join("components", "comp3.spec.yml"), filepath.Join("components", "component.zip"),
					},
					[]string{})
			},
			copy:     io.Copy,
			mkdirAll: os.MkdirAll,
			openFile: os.OpenFile,
		},
		{
			name: "copying file fails",
			args: args{
				version:      "1.2.3",
				archiveFiles: append(archiveFilesWithMoreComponents, agentArchiveSymLink),
				archiveGenerator: func(t *testing.T, i []files) (string, error) {
					return createTarArchive(t, "elastic-agent-1.2.3-SNAPSHOT-someos-x86_64.tar.gz", i)
				},
			},
			expectedError: testError,
			copy: func(dst io.Writer, src io.Reader) (written int64, err error) {
				return 0, testError
			},
			mkdirAll: os.MkdirAll,
			openFile: os.OpenFile,
		},
		{
			name: "opening file fails",
			args: args{
				version:      "1.2.3",
				archiveFiles: append(archiveFilesWithMoreComponents, agentArchiveSymLink),
				archiveGenerator: func(t *testing.T, i []files) (string, error) {
					return createTarArchive(t, "elastic-agent-1.2.3-SNAPSHOT-someos-x86_64.tar.gz", i)
				},
			},
			expectedError: testError,
			openFile: func(name string, flag int, perm os.FileMode) (*os.File, error) {
				return nil, testError
			},
			mkdirAll: os.MkdirAll,
			copy:     io.Copy,
		},
		{
			name: "creating directory fails",
			args: args{
				version:      "1.2.3",
				archiveFiles: append(archiveFilesWithMoreComponents, agentArchiveSymLink),
				archiveGenerator: func(t *testing.T, i []files) (string, error) {
					return createTarArchive(t, "elastic-agent-1.2.3-SNAPSHOT-someos-x86_64.tar.gz", i)
				},
			},
			expectedError: testError,
			mkdirAll: func(name string, perm os.FileMode) error {
				return testError
			},
			openFile: os.OpenFile,
			copy:     io.Copy,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testTop := t.TempDir()
			testDataDir := filepath.Join(testTop, "data")
			err := os.MkdirAll(testDataDir, 0o777)
			assert.NoErrorf(t, err, "error creating initial structure %q", testDataDir)
			log, _ := loggertest.New(tt.name)

			archiveFile, err := tt.args.archiveGenerator(t, tt.args.archiveFiles)
			require.NoError(t, err, "creation of test archive file failed")

			got, err := untar(log, archiveFile, testDataDir, tt.flavor, tt.copy, tt.mkdirAll, tt.openFile)
			if tt.expectedError != nil {
				assert.ErrorIsf(t, err, tt.expectedError, "untar(%v, %v, %v)", tt.args.version, archiveFile, testDataDir)
				return
			}
			assert.NoErrorf(t, err, "untar(%v, %v, %v)", tt.args.version, archiveFile, testDataDir)
			assert.Equalf(t, tt.want, got, "untar(%v, %v, %v)", tt.args.version, archiveFile, testDataDir)
			if tt.checkFiles != nil {
				tt.checkFiles(t, testDataDir)
			}
		})
	}
}

func TestUpgrader_unpackZip(t *testing.T) {
	testError := errors.New("test error")
	type args struct {
		archiveGenerator createArchiveFunc
		archiveFiles     []files
	}

	binarySuffix := ""
	if runtime.GOOS == "windows" {
		binarySuffix = ".exe"
	}

	tests := []struct {
		name          string
		args          args
		want          UnpackResult
		expectedError error
		checkFiles    checkExtractedPath
		flavor        string
		copy          copyFunc
		mkdirAll      mkdirAllFunc
		openFile      openFileFunc
	}{
		{
			name: "file before containing folder",
			args: args{
				archiveFiles: outOfOrderArchiveFilesNoManifestNoSymlink,
				archiveGenerator: func(t *testing.T, i []files) (string, error) {
					return createZipArchive(t, "elastic-agent-1.2.3-SNAPSHOT-someos-x86_64.zip", i)
				},
			},
			want: UnpackResult{
				Hash:          "abcdef",
				VersionedHome: filepath.Join("data", "elastic-agent-abcdef"),
			},
			expectedError: nil,
			checkFiles: func(t *testing.T, testDataDir string) {
				versionedHome := filepath.Join(testDataDir, "elastic-agent-abcdef")
				checkExtractedFilesOutOfOrder(t, versionedHome)
			},
			copy:     io.Copy,
			mkdirAll: os.MkdirAll,
			openFile: os.OpenFile,
		},
		{
			name: "package with manifest file",
			args: args{
				archiveFiles: archiveFilesWithManifestNoSymlink,
				archiveGenerator: func(t *testing.T, i []files) (string, error) {
					return createZipArchive(t, "elastic-agent-1.2.3-SNAPSHOT-someos-x86_64.zip", i)
				},
			},
			want: UnpackResult{
				Hash:          "abcdef",
				VersionedHome: filepath.Join("data", "elastic-agent-1.2.3-SNAPSHOT-abcdef"),
			},
			expectedError: nil,
			checkFiles:    checkExtractedFilesWithManifest,
			copy:          io.Copy,
			mkdirAll:      os.MkdirAll,
			openFile:      os.OpenFile,
		},

		{
			name: "package with basic flavor",
			args: args{
				archiveFiles: archiveFilesWithMoreComponents,
				archiveGenerator: func(t *testing.T, i []files) (string, error) {
					return createZipArchive(t, "elastic-agent-1.2.3-SNAPSHOT-someos-x86_64.zip", i)
				},
			},
			want: UnpackResult{
				Hash:          "abcdef",
				VersionedHome: filepath.Join("data", "elastic-agent-1.2.3-SNAPSHOT-abcdef"),
			},
			expectedError: nil,
			flavor:        "basic",
			checkFiles: func(t *testing.T, testDataDir string) {
				checkFilesPresence(t, testDataDir,
					[]string{
						filepath.Join("components", "comp1"+binarySuffix), filepath.Join("components", "comp1.spec.yml"),
						filepath.Join("components", "comp2"+binarySuffix), filepath.Join("components", "comp2.spec.yml"),
						filepath.Join("components", "component_dir", "inner_file"),
					},
					[]string{filepath.Join("components", "comp3"+binarySuffix), filepath.Join("components", "comp3.spec.yml"), filepath.Join("components", "component.zip")})
			},
			copy:     io.Copy,
			mkdirAll: os.MkdirAll,
			openFile: os.OpenFile,
		},
		{
			name: "package with servers flavor",
			args: args{
				archiveFiles: archiveFilesWithMoreComponents,
				archiveGenerator: func(t *testing.T, i []files) (string, error) {
					return createZipArchive(t, "elastic-agent-1.2.3-SNAPSHOT-someos-x86_64.zip", i)
				},
			},
			want: UnpackResult{
				Hash:          "abcdef",
				VersionedHome: filepath.Join("data", "elastic-agent-1.2.3-SNAPSHOT-abcdef"),
			},
			expectedError: nil,
			flavor:        "servers",
			checkFiles: func(t *testing.T, testDataDir string) {
				checkFilesPresence(t, testDataDir,
					[]string{
						filepath.Join("components", "comp1"+binarySuffix), filepath.Join("components", "comp1.spec.yml"),
						filepath.Join("components", "comp2"+binarySuffix), filepath.Join("components", "comp2.spec.yml"),
						filepath.Join("components", "component_dir", "inner_file"),
						filepath.Join("components", "comp3"+binarySuffix), filepath.Join("components", "comp3.spec.yml"), filepath.Join("components", "component.zip"),
					},
					[]string{})
			},
			copy:     io.Copy,
			mkdirAll: os.MkdirAll,
			openFile: os.OpenFile,
		},
		{
			name: "copying file fails",
			args: args{
				archiveFiles: archiveFilesWithMoreComponents,
				archiveGenerator: func(t *testing.T, i []files) (string, error) {
					return createZipArchive(t, "elastic-agent-1.2.3-SNAPSHOT-someos-x86_64.zip", i)
				},
			},
			expectedError: testError,
			copy: func(dst io.Writer, src io.Reader) (written int64, err error) {
				return 0, testError
			},
			mkdirAll: os.MkdirAll,
			openFile: os.OpenFile,
		},
		{
			name: "opening file fails",
			args: args{
				archiveFiles: archiveFilesWithMoreComponents,
				archiveGenerator: func(t *testing.T, i []files) (string, error) {
					return createZipArchive(t, "elastic-agent-1.2.3-SNAPSHOT-someos-x86_64.zip", i)
				},
			},
			expectedError: testError,
			openFile: func(name string, flag int, perm os.FileMode) (*os.File, error) {
				return nil, testError
			},
			mkdirAll: os.MkdirAll,
			copy:     io.Copy,
		},
		{
			name: "creating directory fails",
			args: args{
				archiveFiles: archiveFilesWithMoreComponents,
				archiveGenerator: func(t *testing.T, i []files) (string, error) {
					return createZipArchive(t, "elastic-agent-1.2.3-SNAPSHOT-someos-x86_64.zip", i)
				},
			},
			expectedError: testError,
			mkdirAll: func(name string, perm os.FileMode) error {
				return testError
			},
			openFile: os.OpenFile,
			copy:     io.Copy,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			testTop := t.TempDir()
			testDataDir := filepath.Join(testTop, "data")
			err := os.MkdirAll(testDataDir, 0o777)
			assert.NoErrorf(t, err, "error creating initial structure %q", testDataDir)
			log, _ := loggertest.New(tt.name)

			archiveFile, err := tt.args.archiveGenerator(t, tt.args.archiveFiles)
			require.NoError(t, err, "creation of test archive file failed")

			got, err := unzip(log, archiveFile, testDataDir, tt.flavor, tt.copy, tt.mkdirAll, tt.openFile)
			if tt.expectedError != nil {
				assert.ErrorIs(t, err, tt.expectedError, "error mismatch")
				return
			}
			assert.NoErrorf(t, err, "unzip(%v, %v)", archiveFile, testDataDir)
			assert.Equalf(t, tt.want, got, "unzip(%v, %v)", archiveFile, testDataDir)
			if tt.checkFiles != nil {
				tt.checkFiles(t, testDataDir)
			}
		})
	}
}

func checkExtractedFilesOutOfOrder(t *testing.T, versionedHome string) {
	require.DirExists(t, versionedHome, "directory for package.version does not exists")
	stat, err := os.Stat(versionedHome)
	require.NoErrorf(t, err, "error calling Stat() for versionedHome %q", versionedHome)
	expectedPermissions := fs.ModePerm & 0o700
	if runtime.GOOS == "windows" {
		// windows permissions are not very fine grained  :/
		expectedPermissions = fs.ModePerm & 0o777
	}
	actualPermissions := fs.ModePerm & stat.Mode()
	assert.Equalf(t, expectedPermissions, actualPermissions, "Wrong permissions set on versioned home %q: expected %O, got %O", versionedHome, expectedPermissions, actualPermissions)
	agentExecutable := filepath.Join(versionedHome, AgentName)
	if assert.FileExistsf(t, agentExecutable, "agent executable %q is not found in versioned home directory %q", agentExecutable, versionedHome) {
		fileBytes, err := os.ReadFile(agentExecutable)
		if assert.NoErrorf(t, err, "error reading elastic-agent executable %q", agentExecutable) {
			assert.Equal(t, agentBinaryPlaceholderContent, string(fileBytes), "agent binary placeholder content does not match")
		}
	}
}

func checkExtractedFilesWithManifest(t *testing.T, testDataDir string) {
	versionedHome := filepath.Join(testDataDir, "elastic-agent-1.2.3-SNAPSHOT-abcdef")
	require.DirExists(t, versionedHome, "mapped versioned home directory does not exists")
	mappedAgentExecutable := filepath.Join(versionedHome, AgentName)
	if assert.FileExistsf(t, mappedAgentExecutable, "agent executable %q is not found in mapped versioned home directory %q", mappedAgentExecutable, versionedHome) {
		fileBytes, err := os.ReadFile(mappedAgentExecutable)
		if assert.NoErrorf(t, err, "error reading elastic-agent executable %q", mappedAgentExecutable) {
			assert.Equal(t, agentBinaryPlaceholderContent, string(fileBytes), "agent binary placeholder content does not match")
		}
	}
	mappedPackageManifest := filepath.Join(versionedHome, v1.ManifestFileName)
	if assert.FileExistsf(t, mappedPackageManifest, "package manifest %q is not found in mapped versioned home directory %q", mappedPackageManifest, versionedHome) {
		fileBytes, err := os.ReadFile(mappedPackageManifest)
		if assert.NoErrorf(t, err, "error reading package manifest %q", mappedPackageManifest) {
			assert.Equal(t, ea_123_manifest, string(fileBytes), "package manifest content does not match")
		}
	}
}

func checkFilesPresence(t *testing.T, testDataDir string, requiredFiles, unwantedFiles []string) {
	versionedHome := filepath.Join(testDataDir, "elastic-agent-1.2.3-SNAPSHOT-abcdef")
	for _, f := range requiredFiles {
		assert.FileExists(t, filepath.Join(versionedHome, f))
	}
	for _, f := range unwantedFiles {
		assert.NoFileExists(t, filepath.Join(versionedHome, f))
	}
}

func createTarArchive(t *testing.T, archiveName string, archiveFiles []files) (string, error) {
	outDir := t.TempDir()

	outFilePath := filepath.Join(outDir, archiveName)
	file, err := os.OpenFile(outFilePath, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0o644)
	require.NoErrorf(t, err, "error creating output archive %q", outFilePath)
	defer func(file *os.File) {
		err := file.Close()
		assert.NoError(t, err, "error closing tar.gz archive file")
	}(file)
	zipWriter := gzip.NewWriter(file)
	writer := tar.NewWriter(zipWriter)
	defer func(writer *tar.Writer) {
		err := writer.Close()
		assert.NoError(t, err, "error closing tar writer")
		err = zipWriter.Close()
		assert.NoError(t, err, "error closing gzip writer")
	}(writer)

	for _, af := range archiveFiles {
		err = addEntryToTarArchive(af, writer)
		require.NoErrorf(t, err, "error adding %q to tar archive", af.path)
	}

	return outFilePath, err
}

func addEntryToTarArchive(af files, writer *tar.Writer) error {
	if af.binary && runtime.GOOS == "windows" {
		af.path += ".exe"
	}

	header, err := tar.FileInfoHeader(&af, af.content)
	if err != nil {
		return fmt.Errorf("creating header for %q: %w", af.path, err)
	}

	header.Name = filepath.ToSlash(af.path)

	if err := writer.WriteHeader(header); err != nil {
		return fmt.Errorf("writing header for %q: %w", af.path, err)
	}

	if af.IsDir() || af.fType == SYMLINK {
		return nil
	}

	if _, err = io.Copy(writer, strings.NewReader(af.content)); err != nil {
		return fmt.Errorf("copying file %q content: %w", af.path, err)
	}
	return nil
}

func createZipArchive(t *testing.T, archiveName string, archiveFiles []files) (string, error) {
	t.Helper()
	outDir := t.TempDir()

	outFilePath := filepath.Join(outDir, archiveName)
	file, err := os.OpenFile(outFilePath, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0o644)
	require.NoErrorf(t, err, "error creating output archive %q", outFilePath)
	defer func(file *os.File) {
		err := file.Close()
		assert.NoError(t, err, "error closing zip archive file")
	}(file)

	w := zip.NewWriter(file)
	defer func(writer *zip.Writer) {
		err := writer.Close()
		assert.NoError(t, err, "error closing tar writer")
	}(w)

	for _, af := range archiveFiles {
		if af.fType == SYMLINK {
			return "", fmt.Errorf("entry %q is a symlink. Not supported in .zip files", af.path)
		}

		err = addEntryToZipArchive(af, w)
		require.NoErrorf(t, err, "error adding %q to tar archive", af.path)
	}
	return outFilePath, nil
}

func addEntryToZipArchive(af files, writer *zip.Writer) error {
	if af.binary && runtime.GOOS == "windows" {
		af.path += ".exe"
	}

	header, err := zip.FileInfoHeader(&af)
	if err != nil {
		return fmt.Errorf("creating header for %q: %w", af.path, err)
	}

	header.SetMode(af.Mode() & os.ModePerm)
	header.Name = filepath.ToSlash(af.path)
	if af.IsDir() {
		header.Name += "/"
	} else {
		header.Method = zip.Deflate
	}

	w, err := writer.CreateHeader(header)
	if err != nil {
		return err
	}

	if af.IsDir() {
		return nil
	}

	if _, err = io.Copy(w, strings.NewReader(af.content)); err != nil {
		return err
	}

	return nil
}

func TestGetFileNamePrefix(t *testing.T) {
	tests := map[string]struct {
		archivePath    string
		expectedPrefix string
	}{
		"fips": {
			archivePath:    "/foo/bar/elastic-agent-fips-9.1.0-SNAPSHOT-linux-arm64.tar.gz",
			expectedPrefix: "elastic-agent-9.1.0-SNAPSHOT-linux-arm64/",
		},
		"no_fips": {
			archivePath:    "/foo/bar/elastic-agent-9.1.0-SNAPSHOT-linux-arm64.tar.gz",
			expectedPrefix: "elastic-agent-9.1.0-SNAPSHOT-linux-arm64/",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			prefix := getFileNamePrefix(test.archivePath)
			require.Equal(t, test.expectedPrefix, prefix)
		})
	}

}

func TestUnpack(t *testing.T) {
	log, _ := loggertest.New("TestUnpack")

	unarchiveSetup := func(unpackResult UnpackResult, err error) unarchiveFunc {
		return func(log *logger.Logger, archivePath, dataDir string, flavor string, copy copyFunc, mkdirAll mkdirAllFunc, openFile openFileFunc) (UnpackResult, error) {
			return unpackResult, err
		}
	}

	type testCase struct {
		expectedUnpackResult UnpackResult
		expectedErr          error
		unarchiveFunc        unarchiveFunc
	}

	testCases := map[string]testCase{
		"when unarchiving succeeds it should return the unpack result": {
			expectedUnpackResult: UnpackResult{
				Hash:          "abcdef",
				VersionedHome: filepath.Join("data", "elastic-agent-abcdef"),
			},
			expectedErr: nil,
			unarchiveFunc: unarchiveSetup(UnpackResult{
				Hash:          "abcdef",
				VersionedHome: filepath.Join("data", "elastic-agent-abcdef"),
			}, nil),
		},
		"when unarchiving fails it should return an error": {
			expectedUnpackResult: UnpackResult{},
			expectedErr:          errors.New("unarchiving failed"),
			unarchiveFunc:        unarchiveSetup(UnpackResult{}, errors.New("unarchiving failed")),
		},
	}

	for name, test := range testCases {
		t.Run(name, func(t *testing.T) {
			unpacker := newUnpacker(log)
			unpacker.untar = test.unarchiveFunc
			unpacker.unzip = test.unarchiveFunc
			unpackResult, unpackErr := unpacker.unpack("mockVersion", "mockArchivePath", "mockDataDir", "mockFlavor")
			assert.Equal(t, test.expectedUnpackResult, unpackResult)
			assert.Equal(t, test.expectedErr, unpackErr)
		})
	}
}
