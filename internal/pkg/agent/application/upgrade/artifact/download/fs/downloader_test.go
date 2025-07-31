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
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact"
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
		wantErr bool
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
			wantErr: false,
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
			wantErr: true,
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
			wantErr: false,
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
			wantErr: false,
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
			wantErr: false,
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

			e := NewDownloader(config)
			got, err := e.Download(context.TODO(), tt.args.a, tt.args.version)

			if tt.wantErr {
				assert.Error(t, err)

				expectedTargetFile := filepath.Join(targetDirPath, tt.want)
				expectedHashFile := expectedTargetFile + ".sha512"

				assert.NoFileExists(t, expectedTargetFile, "downloader should clean up partial artifact file on error")
				assert.NoFileExists(t, expectedHashFile, "downloader should clean up partial hash file on error")
				assert.NoDirExists(t, targetDirPath, "downloader should clean up target directory on error")
				return
			}

			assert.NoError(t, err)
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

			e := NewDownloader(config)
			got, err := e.DownloadAsc(context.TODO(), tt.args.a, tt.args.version)
			if !tt.wantErr(t, err, fmt.Sprintf("DownloadAsc(%v, %v)", tt.args.a, tt.args.version)) {
				return
			}
			assert.Equalf(t, filepath.Join(targetDirPath, tt.want), got, "DownloadAsc(%v, %v)", tt.args.a, tt.args.version)
		})
	}
}

type testCopyError struct {
	msg string
}

func (e *testCopyError) Error() string {
	return e.msg
}

func (e *testCopyError) Is(target error) bool {
	_, ok := target.(*testCopyError)
	return ok
}

func TestDownloader_downloadFile(t *testing.T) {
	dropPath := t.TempDir()
	targetDirPath := t.TempDir()

	createFiles(t, dropPath, []file{
		{
			"elastic-agent-1.2.3-linux-x86_64.tar.gz",
			[]byte("mock content"),
		},
	})

	config := &artifact.Config{
		DropPath:        dropPath,
		TargetDirectory: targetDirPath,
	}

	var receivedError error
	diskSpaceErr := errors.New("disk space error")
	diskSpaceErrorFunc := func(err error) error {
		receivedError = err
		return diskSpaceErr
	}

	copyFuncError := &testCopyError{msg: "mock error"}

	copyFunc := func(dst io.Writer, src io.Reader) (int64, error) {
		return 0, copyFuncError
	}
	e := NewDownloader(config)
	e.CopyFunc = copyFunc
	e.diskSpaceErrorFunc = diskSpaceErrorFunc

	path, err := e.downloadFile("elastic-agent-1.2.3-linux-x86_64.tar.gz", filepath.Join(targetDirPath, "elastic-agent-1.2.3-linux-x86_64.tar.gz"))
	assert.Equal(t, err, diskSpaceErr)
	assert.Equal(t, receivedError, copyFuncError)
	assert.Equal(t, filepath.Join(targetDirPath, "elastic-agent-1.2.3-linux-x86_64.tar.gz"), path)
}

func TestDownloader_NewDownloader(t *testing.T) {
	dropPath := t.TempDir()
	config := &artifact.Config{
		OperatingSystem: "linux",
		Architecture:    "64",
		DropPath:        dropPath,
	}

	downloader := NewDownloader(config)

	expectedCopyFunc := reflect.ValueOf(io.Copy).Pointer()
	actualCopyFunc := reflect.ValueOf(downloader.CopyFunc).Pointer()
	assert.Equal(t, expectedCopyFunc, actualCopyFunc)
	assert.Equal(t, config, downloader.config)
}
