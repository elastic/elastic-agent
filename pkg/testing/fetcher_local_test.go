// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package testing

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLocalFetcher_Name(t *testing.T) {
	f := LocalFetcher(t.TempDir())
	require.Equal(t, "local", f.Name())
}

func TestLocalFetcher(t *testing.T) {
	// t.Skip()
	baseVersion := "8.7.0"
	snapshotContent := []byte("snapshot contents")
	snapshotContentHash := []byte("snapshot contents hash")
	noSnapshotContent := []byte("not snapshot contents")
	noSnapshotContentHash := []byte("not snapshot contents hash")
	pkgFormat := "targz"
	if runtime.GOOS == "windows" {
		pkgFormat = "zip"
	}

	testdata := t.TempDir()
	suffix, err := GetPackageSuffix(runtime.GOOS, runtime.GOARCH, pkgFormat)
	require.NoError(t, err)

	snapshotPath := fmt.Sprintf("elastic-agent-%s-SNAPSHOT-%s", baseVersion, suffix)
	require.NoError(t, os.WriteFile(filepath.Join(testdata, snapshotPath), snapshotContent, 0644))
	snapshotPathHash := fmt.Sprintf("elastic-agent-%s-SNAPSHOT-%s%s", baseVersion, suffix, extHash)
	require.NoError(t, os.WriteFile(filepath.Join(testdata, snapshotPathHash), snapshotContentHash, 0644))

	notSnapshotPath := fmt.Sprintf("elastic-agent-%s-%s", baseVersion, suffix)
	require.NoError(t, os.WriteFile(filepath.Join(testdata, notSnapshotPath), noSnapshotContent, 0644))
	notSnapshotPathHash := fmt.Sprintf("elastic-agent-%s-%s%s", baseVersion, suffix, extHash)
	require.NoError(t, os.WriteFile(filepath.Join(testdata, notSnapshotPathHash), noSnapshotContentHash, 0644))

	buildID := "l5snflwr"
	require.NoError(t, os.MkdirAll(filepath.Join(testdata, buildID), 0755))
	buildSnapshotPath := filepath.Join(buildID, fmt.Sprintf("elastic-agent-%s-SNAPSHOT-%s", baseVersion, suffix))
	require.NoError(t, os.WriteFile(filepath.Join(testdata, buildSnapshotPath), snapshotContent, 0644))
	buildSnapshotPathHash := buildSnapshotPath + extHash
	require.NoError(t, os.WriteFile(filepath.Join(testdata, buildSnapshotPathHash), snapshotContentHash, 0644))

	tcs := []struct {
		name     string
		version  string
		opts     []localFetcherOpt
		want     []byte
		wantHash []byte
	}{
		{
			name:     "IgnoreSnapshot",
			version:  baseVersion,
			want:     noSnapshotContent,
			wantHash: noSnapshotContentHash,
		}, {
			name:     "SnapshotOnly",
			version:  baseVersion,
			opts:     []localFetcherOpt{WithLocalSnapshotOnly()},
			want:     snapshotContent,
			wantHash: snapshotContentHash,
		}, {
			name:     "version with snapshot",
			version:  baseVersion + "-SNAPSHOT",
			want:     snapshotContent,
			wantHash: snapshotContentHash,
		}, {
			name:     "version with snapshot and SnapshotOnly",
			version:  baseVersion + "-SNAPSHOT",
			opts:     []localFetcherOpt{WithLocalSnapshotOnly()},
			want:     snapshotContent,
			wantHash: snapshotContentHash,
		}, {
			name:     "version with snapshot and build ID",
			version:  baseVersion + "-SNAPSHOT+l5snflwr",
			opts:     []localFetcherOpt{},
			want:     snapshotContent,
			wantHash: snapshotContentHash,
		},
	}

	for _, tc := range tcs {
		tmp := t.TempDir()

		f := LocalFetcher(testdata, tc.opts...)
		pkgFormat := "targz"
		if runtime.GOOS == "windows" {
			pkgFormat = "zip"
		}
		got, err := f.Fetch(
			context.Background(), runtime.GOOS, runtime.GOARCH, tc.version, pkgFormat)
		require.NoError(t, err)

		err = got.Fetch(context.Background(), t, tmp)
		require.NoError(t, err)
		content, err := os.ReadFile(filepath.Join(tmp, got.Name()))
		require.NoError(t, err)

		assert.Equal(t, string(tc.want), string(content))
		contentHash, err := os.ReadFile(filepath.Join(tmp, got.Name()+extHash))
		require.NoError(t, err)

		assert.Equal(t, string(tc.wantHash), string(contentHash))
	}
}
