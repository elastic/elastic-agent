// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package fs

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact"
	downloadErrors "github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact/download/errors"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/common"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	agtversion "github.com/elastic/elastic-agent/pkg/version"
)

type file struct {
	Name string
	Body []byte
}

func TestDownloader_Download(t *testing.T) {
	type fields struct {
		config *artifact.Config
	}
	type args struct {
		a       artifact.Artifact
		version *agtversion.ParsedSemVer
	}
	tests := []struct {
		name    string
		files   []file
		fields  fields
		args    args
		want    string
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name: "happy path released version",
			files: []file{
				{
					"elastic-agent-1.2.3-linux-x86_64.tar.gz",
					[]byte("This is a fake linux elastic agent archive"),
				},
				{
					"elastic-agent-1.2.3-linux-x86_64.tar.gz.sha512",
					[]byte("somesha512 elastic-agent-1.2.3-linux-x86_64.tar.gz"),
				},
			},
			fields: fields{
				config: &artifact.Config{
					OperatingSystem: "linux",
					Architecture:    "64",
				},
			},
			args:    args{a: agentSpec, version: agtversion.NewParsedSemVer(1, 2, 3, "", "")},
			want:    "elastic-agent-1.2.3-linux-x86_64.tar.gz",
			wantErr: assert.NoError,
		},
		{
			name: "no hash released version",
			files: []file{
				{
					"elastic-agent-1.2.3-linux-x86_64.tar.gz",
					[]byte("This is a fake linux elastic agent archive"),
				},
			},
			fields: fields{
				config: &artifact.Config{
					OperatingSystem: "linux",
					Architecture:    "64",
				},
			},
			args:    args{a: agentSpec, version: agtversion.NewParsedSemVer(1, 2, 3, "", "")},
			want:    "elastic-agent-1.2.3-linux-x86_64.tar.gz",
			wantErr: assert.Error,
		},
		{
			name: "happy path snapshot version",
			files: []file{
				{
					"elastic-agent-1.2.3-SNAPSHOT-linux-x86_64.tar.gz",
					[]byte("This is a fake linux elastic agent archive"),
				},
				{
					"elastic-agent-1.2.3-SNAPSHOT-linux-x86_64.tar.gz.sha512",
					[]byte("somesha512 elastic-agent-1.2.3-SNAPSHOT-linux-x86_64.tar.gz"),
				},
			},
			fields: fields{
				config: &artifact.Config{
					OperatingSystem: "linux",
					Architecture:    "64",
				},
			},
			args:    args{a: agentSpec, version: agtversion.NewParsedSemVer(1, 2, 3, "SNAPSHOT", "")},
			want:    "elastic-agent-1.2.3-SNAPSHOT-linux-x86_64.tar.gz",
			wantErr: assert.NoError,
		},
		{
			name: "happy path released version with build metadata",
			files: []file{
				{
					"elastic-agent-1.2.3+build19700101-linux-x86_64.tar.gz",
					[]byte("This is a fake linux elastic agent archive"),
				},
				{
					"elastic-agent-1.2.3+build19700101-linux-x86_64.tar.gz.sha512",
					[]byte("somesha512 elastic-agent-1.2.3+build19700101-linux-x86_64.tar.gz"),
				},
			},
			fields: fields{
				config: &artifact.Config{
					OperatingSystem: "linux",
					Architecture:    "64",
				},
			},
			args:    args{a: agentSpec, version: agtversion.NewParsedSemVer(1, 2, 3, "", "build19700101")},
			want:    "elastic-agent-1.2.3+build19700101-linux-x86_64.tar.gz",
			wantErr: assert.NoError,
		},
		{
			name: "happy path snapshot version with build metadata",
			files: []file{
				{
					"elastic-agent-1.2.3-SNAPSHOT+build19700101-linux-x86_64.tar.gz",
					[]byte("This is a fake linux elastic agent archive"),
				},
				{
					"elastic-agent-1.2.3-SNAPSHOT+build19700101-linux-x86_64.tar.gz.sha512",
					[]byte("somesha512 elastic-agent-1.2.3-SNAPSHOT+build19700101-linux-x86_64.tar.gz"),
				},
			},
			fields: fields{
				config: &artifact.Config{
					OperatingSystem: "linux",
					Architecture:    "64",
				},
			},
			args:    args{a: agentSpec, version: agtversion.NewParsedSemVer(1, 2, 3, "SNAPSHOT", "build19700101")},
			want:    "elastic-agent-1.2.3-SNAPSHOT+build19700101-linux-x86_64.tar.gz",
			wantErr: assert.NoError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			dropPath := t.TempDir()
			targetDirPath := t.TempDir()

			createFiles(t, dropPath, tt.files)

			config := tt.fields.config
			config.DropPath = dropPath
			config.TargetDirectory = targetDirPath

			e := &Downloader{
				dropPath: dropPath,
				config:   config,
			}
			got, err := e.Download(context.TODO(), tt.args.a, tt.args.version)
			if !tt.wantErr(t, err, fmt.Sprintf("Download(%v, %v)", tt.args.a, tt.args.version)) {
				return
			}
			assert.Equalf(t, filepath.Join(targetDirPath, tt.want), got, "Download(%v, %v)", tt.args.a, tt.args.version)
		})
	}
}

func createFiles(t *testing.T, dstPath string, files []file) {
	for _, f := range files {
		dstFile := filepath.Join(dstPath, f.Name)
		err := os.WriteFile(dstFile, f.Body, 0o666)
		require.NoErrorf(t, err, "error preparing file %s: %v", dstFile, err)
	}
}

func TestDownloader_DownloadAsc(t *testing.T) {
	type fields struct {
		config *artifact.Config
	}
	type args struct {
		a       artifact.Artifact
		version agtversion.ParsedSemVer
	}
	tests := []struct {
		name    string
		files   []file
		fields  fields
		args    args
		want    string
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name: "happy path released version",
			files: []file{
				{
					"elastic-agent-1.2.3-linux-x86_64.tar.gz.asc",
					[]byte("fake signature for elastic-agent package"),
				},
			},
			fields: fields{
				config: &artifact.Config{
					OperatingSystem: "linux",
					Architecture:    "64",
				},
			},
			args:    args{a: agentSpec, version: *agtversion.NewParsedSemVer(1, 2, 3, "", "")},
			want:    "elastic-agent-1.2.3-linux-x86_64.tar.gz.asc",
			wantErr: assert.NoError,
		},
		{
			name: "happy path snapshot version",
			files: []file{
				{
					"elastic-agent-1.2.3-SNAPSHOT-linux-x86_64.tar.gz.asc",
					[]byte("fake signature for elastic-agent package"),
				},
			},
			fields: fields{
				config: &artifact.Config{
					OperatingSystem: "linux",
					Architecture:    "64",
				},
			},
			args:    args{a: agentSpec, version: *agtversion.NewParsedSemVer(1, 2, 3, "SNAPSHOT", "")},
			want:    "elastic-agent-1.2.3-SNAPSHOT-linux-x86_64.tar.gz.asc",
			wantErr: assert.NoError,
		},
		{
			name: "happy path released version with build metadata",
			files: []file{
				{
					"elastic-agent-1.2.3+build19700101-linux-x86_64.tar.gz.asc",
					[]byte("fake signature for elastic-agent package"),
				},
			},
			fields: fields{
				config: &artifact.Config{
					OperatingSystem: "linux",
					Architecture:    "64",
				},
			},
			args:    args{a: agentSpec, version: *agtversion.NewParsedSemVer(1, 2, 3, "", "build19700101")},
			want:    "elastic-agent-1.2.3+build19700101-linux-x86_64.tar.gz.asc",
			wantErr: assert.NoError,
		},
		{
			name: "happy path snapshot version with build metadata",
			files: []file{
				{
					"elastic-agent-1.2.3-SNAPSHOT+build19700101-linux-x86_64.tar.gz.asc",
					[]byte("fake signature for elastic-agent package"),
				},
			},
			fields: fields{
				config: &artifact.Config{
					OperatingSystem: "linux",
					Architecture:    "64",
				},
			},
			args:    args{a: agentSpec, version: *agtversion.NewParsedSemVer(1, 2, 3, "SNAPSHOT", "build19700101")},
			want:    "elastic-agent-1.2.3-SNAPSHOT+build19700101-linux-x86_64.tar.gz.asc",
			wantErr: assert.NoError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dropPath := t.TempDir()
			targetDirPath := t.TempDir()

			createFiles(t, dropPath, tt.files)

			config := tt.fields.config
			config.DropPath = dropPath
			config.TargetDirectory = targetDirPath

			e := &Downloader{
				dropPath: dropPath,
				config:   config,
			}
			got, err := e.DownloadAsc(context.TODO(), tt.args.a, tt.args.version)
			if !tt.wantErr(t, err, fmt.Sprintf("DownloadAsc(%v, %v)", tt.args.a, tt.args.version)) {
				return
			}
			assert.Equalf(t, filepath.Join(targetDirPath, tt.want), got, "DownloadAsc(%v, %v)", tt.args.a, tt.args.version)
		})
	}
}

func TestDownloadDiskSpaceError(t *testing.T) {

	testCases := map[string]struct {
		mockReturnedError error
		expectedError     error
	}{
		"when fs downloader runs into a generic error, it should return error and clean up the downloaded file": {
			mockReturnedError: errors.New("test error"),
			expectedError:     errors.New("test error"),
		},
	}

	for _, osErr := range downloadErrors.OS_DiskSpaceErrors {
		testCases[fmt.Sprintf("when fs downloader runs into disk space error, it should return insufficient disk space error and clean up the downloaded file: %v", osErr)] = struct {
			mockReturnedError error
			expectedError     error
		}{
			mockReturnedError: osErr,
			expectedError:     osErr,
		}
	}

	funcNames := []common.MockStdLibFuncName{common.CopyFuncName, common.OpenFileFuncName, common.MkdirAllFuncName}

	for testName, tc := range testCases {
		for _, funcName := range funcNames {
			t.Run(fmt.Sprintf("%s-%s", testName, funcName), func(t *testing.T) {
				stdLibMocker := common.PrepareStdLibMocks(common.StdLibMocks{
					CopyMock: func(dst io.Writer, src io.Reader) (int64, error) {
						return 0, tc.mockReturnedError
					},
					OpenFileMock: func(name string, flag int, perm os.FileMode) (*os.File, error) {
						return nil, tc.mockReturnedError
					},
					MkdirAllMock: func(path string, perm os.FileMode) error {
						return tc.mockReturnedError
					},
				})

				stdLibMocker(t, funcName)

				baseDir := t.TempDir()
				paths.SetTop(baseDir)
				config := &artifact.Config{
					DropPath:        filepath.Join(baseDir, "drop"),
					TargetDirectory: filepath.Join(baseDir, "target"),
				}

				err := os.MkdirAll(config.DropPath, 0o755)
				require.NoError(t, err)

				err = os.MkdirAll(config.TargetDirectory, 0o755)
				require.NoError(t, err)

				parsedVersion := agtversion.NewParsedSemVer(1, 2, 3, "", "")

				artifactName, err := artifact.GetArtifactName(agentSpec, *parsedVersion, config.OS(), config.Arch())
				require.NoError(t, err)

				sourceArtifactPath := filepath.Join(config.DropPath, artifactName)
				sourceArtifactHashPath := sourceArtifactPath + ".sha512"

				err = os.WriteFile(sourceArtifactPath, []byte("test"), 0o666)
				require.NoError(t, err, "failed to create source artifact file")

				err = os.WriteFile(sourceArtifactHashPath, []byte("test"), 0o666)
				require.NoError(t, err, "failed to create source artifact hash file")

				downloader := NewDownloader(config)
				targetArtifactPath, err := downloader.Download(context.Background(), agentSpec, parsedVersion)

				require.ErrorIs(t, err, tc.expectedError)

				require.NoFileExists(t, targetArtifactPath)
			})
		}
	}
}
