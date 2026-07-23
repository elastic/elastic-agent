// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package upgrade

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-libs/transport/httpcommon"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact"
	upgradeErrors "github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact/download/errors"
	"github.com/elastic/elastic-agent/pkg/upgrade/details"
)

func makeGzipArtifact(t *testing.T, content string) ([]byte, uint64) {
	t.Helper()
	var buf bytes.Buffer
	gzw := gzip.NewWriter(&buf)
	_, err := io.WriteString(gzw, content)
	require.NoError(t, err)
	require.NoError(t, gzw.Close())
	return buf.Bytes(), uint64(len(content))
}

func makeZipArtifact(t *testing.T, files map[string]string) ([]byte, uint64) {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	var payload uint64
	for name, content := range files {
		f, err := zw.Create(name)
		require.NoError(t, err)
		_, err = io.WriteString(f, content)
		require.NoError(t, err)
		payload += uint64(len(content))
	}
	require.NoError(t, zw.Close())
	return buf.Bytes(), payload
}

func makeHugeZipArtifact(entries int) []byte {
	// mock zip central directory plus EOCD with fake entries
	entry := make([]byte, 46)
	entry[0], entry[1], entry[2], entry[3] = 'P', 'K', 0x01, 0x02
	binary.LittleEndian.PutUint32(entry[24:28], 0xFFFFFFFF) // uncompressed size

	var buf bytes.Buffer
	for range entries {
		buf.Write(entry)
	}

	eocd := make([]byte, 22)
	eocd[0], eocd[1], eocd[2], eocd[3] = 'P', 'K', 0x05, 0x06
	var cdSize uint32
	for range entries {
		cdSize += 46
	}
	binary.LittleEndian.PutUint32(eocd[12:16], cdSize) // central directory size
	binary.LittleEndian.PutUint32(eocd[16:20], 0)      // central directory offset
	buf.Write(eocd)

	return buf.Bytes()
}

func diskspaceTestConfig(t *testing.T) *artifact.Config {
	t.Helper()
	return &artifact.Config{
		TargetDirectory:        t.TempDir(),
		RetrySleepInitDuration: time.Millisecond,
		HTTPTransportSettings: httpcommon.HTTPTransportSettings{
			Timeout: time.Second,
		},
	}
}

func TestGetUpgradeSize(t *testing.T) {
	upgradeDetails := func() *details.Details {
		return details.NewDetails("9.0.0", details.StateRequested, "")
	}

	t.Run("local tar.gz", func(t *testing.T) {
		archive, payload := makeGzipArtifact(t, "some artifact content")
		target := filepath.Join(t.TempDir(), "elastic-agent.tar.gz")
		require.NoError(t, os.WriteFile(target, archive, 0o644))

		archiveSize, payloadSize, err := getLocalUpgradeSize("file://" + target)
		require.NoError(t, err)
		require.Equal(t, uint64(len(archive)), archiveSize)
		require.Equal(t, payload, payloadSize)
	})

	t.Run("local zip", func(t *testing.T) {
		archive, payload := makeZipArtifact(t, map[string]string{
			"elastic-agent/one.txt": "first file content",
			"elastic-agent/two.txt": "second file content, slightly longer",
		})
		target := filepath.Join(t.TempDir(), "elastic-agent.zip")
		require.NoError(t, os.WriteFile(target, archive, 0o644))

		archiveSize, payloadSize, err := getLocalUpgradeSize("file://" + target)
		require.NoError(t, err)
		require.Equal(t, uint64(len(archive)), archiveSize)
		require.Equal(t, payload, payloadSize)
	})

	t.Run("local file missing", func(t *testing.T) {
		uri := "file://" + filepath.Join(t.TempDir(), "missing.tar.gz")

		archiveSize, payloadSize, err := getLocalUpgradeSize(uri)
		require.ErrorContains(t, err, "could not stat")
		require.Equal(t, fallbackArchiveSize, archiveSize)
		require.Equal(t, fallbackPayloadSize, payloadSize)
	})

	t.Run("http tar.gz", func(t *testing.T) {
		archive, payload := makeGzipArtifact(t, "some artifact content")
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.ServeContent(w, r, r.URL.Path, time.Time{}, bytes.NewReader(archive))
		}))
		t.Cleanup(server.Close)

		archiveSize, payloadSize, err := getHTTPUpgradeSize(t.Context(), diskspaceTestConfig(t), server.URL+"/elastic-agent.tar.gz", upgradeDetails())
		require.NoError(t, err)
		require.Equal(t, uint64(len(archive)), archiveSize)
		require.Equal(t, payload, payloadSize)
	})

	t.Run("http zip", func(t *testing.T) {
		archive, payload := makeZipArtifact(t, map[string]string{
			"elastic-agent/one.txt": "abcd",
			"elastic-agent/two.txt": "abcdefg",
		})
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.ServeContent(w, r, r.URL.Path, time.Time{}, bytes.NewReader(archive))
		}))
		t.Cleanup(server.Close)

		archiveSize, payloadSize, err := getHTTPUpgradeSize(t.Context(), diskspaceTestConfig(t), server.URL+"/elastic-agent.zip", upgradeDetails())
		require.NoError(t, err)
		require.Equal(t, uint64(len(archive)), archiveSize)
		require.Equal(t, payload, payloadSize)
	})

	t.Run("http response 404 stops retries", func(t *testing.T) {
		var requests int
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requests++
			w.WriteHeader(http.StatusNotFound)
		}))
		t.Cleanup(server.Close)

		_, _, err := getHTTPUpgradeSize(t.Context(), diskspaceTestConfig(t), server.URL+"/elastic-agent.tar.gz", upgradeDetails())
		require.Error(t, err)
		require.True(t, upgradeErrors.IsPermanentHTTPError(err))
		require.Equal(t, 1, requests)
	})

	t.Run("http server without range support stops retries", func(t *testing.T) {
		archive, _ := makeGzipArtifact(t, "some artifact content")
		var getRequests int
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Length", strconv.Itoa(len(archive)))
			if r.Method == http.MethodHead {
				return
			}
			getRequests++
			// servers that don't support Range respond with 200
			_, _ = w.Write(archive)
		}))
		t.Cleanup(server.Close)

		_, _, err := getHTTPUpgradeSize(t.Context(), diskspaceTestConfig(t), server.URL+"/elastic-agent.tar.gz", upgradeDetails())
		require.ErrorContains(t, err, "does not support range requests")
		require.True(t, upgradeErrors.IsPermanentHTTPError(err))
		require.Equal(t, 1, getRequests)
	})

	t.Run("http 416 Range Not Satisfiable is not retried", func(t *testing.T) {
		archive, _ := makeGzipArtifact(t, "some artifact content")
		var getRequests int
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodHead {
				w.Header().Set("Content-Length", strconv.Itoa(len(archive)))
				return
			}
			getRequests++
			w.WriteHeader(http.StatusRequestedRangeNotSatisfiable)
		}))
		t.Cleanup(server.Close)

		_, _, err := getHTTPUpgradeSize(t.Context(), diskspaceTestConfig(t), server.URL+"/elastic-agent.tar.gz", upgradeDetails())
		require.ErrorContains(t, err, "out of range")
		require.True(t, upgradeErrors.IsPermanentHTTPError(err))
		require.Equal(t, 1, getRequests)
	})

	t.Run("http transient errors are retried", func(t *testing.T) {
		archive, payload := makeGzipArtifact(t, "some artifact content")
		var requests int
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requests++
			if requests <= 2 {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			http.ServeContent(w, r, r.URL.Path, time.Time{}, bytes.NewReader(archive))
		}))
		t.Cleanup(server.Close)

		archiveSize, payloadSize, err := getHTTPUpgradeSize(t.Context(), diskspaceTestConfig(t), server.URL+"/elastic-agent.tar.gz", upgradeDetails())
		require.NoError(t, err)
		require.Equal(t, uint64(len(archive)), archiveSize)
		require.Equal(t, payload, payloadSize)
		require.GreaterOrEqual(t, requests, 4) // two failed attempts, then HEAD + range GET
	})
}

func TestCheckDiskSpaceAvailable(t *testing.T) {
	originalTop := paths.Top()
	paths.SetTop(t.TempDir())
	t.Cleanup(func() { paths.SetTop(originalTop) })
	require.NoError(t, os.MkdirAll(paths.Data(), 0o755))

	upgradeDetails := details.NewDetails("9.0.0", details.StateRequested, "")

	t.Run("diskspace is sufficient", func(t *testing.T) {
		archive, _ := makeGzipArtifact(t, "some artifact content")
		target := filepath.Join(t.TempDir(), "elastic-agent.tar.gz")
		require.NoError(t, os.WriteFile(target, archive, 0o644))

		hasSpace, err := CheckDiskSpaceAvailable(t.Context(), diskspaceTestConfig(t), upgradeDetails, "file://"+target)
		require.NoError(t, err)
		require.True(t, hasSpace)
	})

	t.Run("diskspace is insufficient", func(t *testing.T) {
		// mock file has 4096 entries of ~4 GiB (~16 TiB of payload content)
		archive := makeHugeZipArtifact(4096)
		target := filepath.Join(t.TempDir(), "elastic-agent.zip")
		require.NoError(t, os.WriteFile(target, archive, 0o644))

		hasSpace, err := CheckDiskSpaceAvailable(t.Context(), diskspaceTestConfig(t), upgradeDetails, "file://"+target)
		require.False(t, hasSpace)
		require.ErrorContains(t, err, "insufficient space")
	})

	t.Run("required diskspace cannot be determined", func(t *testing.T) {
		uri := "file://" + filepath.Join(t.TempDir(), "missing.tar.gz")

		_, err := CheckDiskSpaceAvailable(t.Context(), diskspaceTestConfig(t), upgradeDetails, uri)
		require.ErrorContains(t, err, "could not get upgrade size")
		require.ErrorContains(t, err, "could not stat")
	})

}
