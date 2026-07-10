// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package manifest

import (
	"context"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	artifactdownload "github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact/download"
)

func checksumLineFor(content []byte, name string) string {
	hash := sha512.Sum512(content)
	return fmt.Sprintf("%s  %s\n", hex.EncodeToString(hash[:]), name)
}

func useFastBackoffSchedule(t *testing.T) {
	t.Helper()
	original := backoffSchedule
	backoffSchedule = []time.Duration{time.Millisecond, time.Millisecond, time.Millisecond}
	t.Cleanup(func() { backoffSchedule = original })
}

func TestDownloadArtifactWithChecksum_Success(t *testing.T) {
	dir := t.TempDir()
	artifactPath := filepath.Join(dir, "artifact.tar.gz")
	shaPath := artifactPath + ".sha512"
	content := []byte("the-real-artifact-bytes")
	checksumLine := checksumLineFor(content, filepath.Base(artifactPath))

	var shaFetches, artifactFetches int
	fetch := func(_ context.Context, url, target string) error {
		if strings.HasSuffix(url, ".sha512") {
			shaFetches++
			return os.WriteFile(target, []byte(checksumLine), 0o644)
		}
		artifactFetches++
		return os.WriteFile(target, content, 0o644)
	}

	err := downloadArtifactWithChecksum(context.Background(), fetch, "https://example.com/artifact.tar.gz", artifactPath, "https://example.com/artifact.tar.gz.sha512", shaPath)
	require.NoError(t, err)
	assert.Equal(t, 1, shaFetches)
	assert.Equal(t, 1, artifactFetches)

	// the sha512 file must be fetched before the artifact
	got, err := os.ReadFile(artifactPath)
	require.NoError(t, err)
	assert.Equal(t, content, got)
}

func TestDownloadArtifactWithChecksum_RetriesOnMismatchThenSucceeds(t *testing.T) {
	useFastBackoffSchedule(t)

	dir := t.TempDir()
	artifactPath := filepath.Join(dir, "artifact.tar.gz")
	shaPath := artifactPath + ".sha512"

	staleContent := []byte("mismatched-bytes")
	freshContent := []byte("matching-bytes")
	checksumLine := checksumLineFor(freshContent, filepath.Base(artifactPath))

	var artifactFetches int
	fetch := func(_ context.Context, url, target string) error {
		if strings.HasSuffix(url, ".sha512") {
			return os.WriteFile(target, []byte(checksumLine), 0o644)
		}
		artifactFetches++
		if artifactFetches == 1 {
			return os.WriteFile(target, staleContent, 0o644)
		}
		return os.WriteFile(target, freshContent, 0o644)
	}

	err := downloadArtifactWithChecksum(context.Background(), fetch, "https://example.com/artifact.tar.gz", artifactPath, "https://example.com/artifact.tar.gz.sha512", shaPath)
	require.NoError(t, err)
	assert.Equal(t, 2, artifactFetches)

	got, err := os.ReadFile(artifactPath)
	require.NoError(t, err)
	assert.Equal(t, freshContent, got)
}

func TestDownloadArtifactWithChecksum_CancelledDuringBackoff(t *testing.T) {
	original := backoffSchedule
	backoffSchedule = []time.Duration{2 * time.Second}
	t.Cleanup(func() { backoffSchedule = original })

	dir := t.TempDir()
	artifactPath := filepath.Join(dir, "artifact.tar.gz")
	shaPath := artifactPath + ".sha512"

	// the sha512 file will never match the artifact, forcing a retry that
	// waits out the (long) backoff above
	checksumLine := checksumLineFor([]byte("does-not-match-what-is-downloaded"), filepath.Base(artifactPath))
	fetch := func(_ context.Context, url, target string) error {
		if strings.HasSuffix(url, ".sha512") {
			return os.WriteFile(target, []byte(checksumLine), 0o644)
		}
		return os.WriteFile(target, []byte("stale-bytes"), 0o644)
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	err := downloadArtifactWithChecksum(ctx, fetch, "https://example.com/artifact.tar.gz", artifactPath, "https://example.com/artifact.tar.gz.sha512", shaPath)
	elapsed := time.Since(start)

	require.ErrorIs(t, err, context.Canceled)
	assert.Less(t, elapsed, 2*time.Second, "should return as soon as the context is cancelled, not wait out the full backoff")
}

func TestDownloadArtifactWithChecksum_FailsAfterExhaustingRetries(t *testing.T) {
	useFastBackoffSchedule(t)

	dir := t.TempDir()
	artifactPath := filepath.Join(dir, "artifact.tar.gz")
	shaPath := artifactPath + ".sha512"

	staleContent := []byte("mismatched-bytes")
	freshContent := []byte("matching-bytes")
	checksumLine := checksumLineFor(freshContent, filepath.Base(artifactPath))

	var artifactFetches int
	fetch := func(_ context.Context, url, target string) error {
		if strings.HasSuffix(url, ".sha512") {
			return os.WriteFile(target, []byte(checksumLine), 0o644)
		}
		artifactFetches++
		// always serve stale bytes: checksum never matches
		return os.WriteFile(target, staleContent, 0o644)
	}

	err := downloadArtifactWithChecksum(context.Background(), fetch, "https://example.com/artifact.tar.gz", artifactPath, "https://example.com/artifact.tar.gz.sha512", shaPath)
	require.Error(t, err)
	var mismatchErr *artifactdownload.ChecksumMismatchError
	assert.True(t, errors.As(err, &mismatchErr), "expected error to wrap a ChecksumMismatchError, got: %v", err)
	assert.Equal(t, len(backoffSchedule), artifactFetches)

	// local copies of the last (mismatched) attempt must not be left behind
	_, err = os.Stat(artifactPath)
	assert.True(t, os.IsNotExist(err))
	_, err = os.Stat(shaPath)
	assert.True(t, os.IsNotExist(err))
}

func TestDownloadArtifactWithChecksum_NonChecksumErrorFailsFast(t *testing.T) {
	dir := t.TempDir()
	artifactPath := filepath.Join(dir, "artifact.tar.gz")
	shaPath := artifactPath + ".sha512"

	boom := errors.New("boom")
	var artifactFetches int
	fetch := func(_ context.Context, url, target string) error {
		if strings.HasSuffix(url, ".sha512") {
			return os.WriteFile(target, []byte("deadbeef  artifact.tar.gz\n"), 0o644)
		}
		artifactFetches++
		return boom
	}

	err := downloadArtifactWithChecksum(context.Background(), fetch, "https://example.com/artifact.tar.gz", artifactPath, "https://example.com/artifact.tar.gz.sha512", shaPath)
	require.Error(t, err)
	assert.True(t, errors.Is(err, boom))
	assert.Equal(t, 1, artifactFetches, "should not retry on a plain download error")
}
