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
	"math"
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

func TestReserveFileSpace(t *testing.T) {
	t.Run("make new reservation", func(t *testing.T) {
		const size = int64(1024*1024 + 123)
		path := filepath.Join(t.TempDir(), "reservation")

		require.NoError(t, reserveDiskSpace(path, size))

		info, err := os.Stat(path)
		require.NoError(t, err)
		require.Equal(t, size, info.Size())
	})

	t.Run("grow pre-existing reservation", func(t *testing.T) {
		const size = int64(1024 * 1024)
		path := filepath.Join(t.TempDir(), "reservation")

		require.NoError(t, reserveDiskSpace(path, size))
		require.NoError(t, reserveDiskSpace(path, 2*size))

		info, err := os.Stat(path)
		require.NoError(t, err)
		require.Equal(t, 2*size, info.Size())
	})

	t.Run("shrink pre-existing reservation", func(t *testing.T) {
		const size = int64(1024 * 1024)
		path := filepath.Join(t.TempDir(), "reservation")

		require.NoError(t, reserveDiskSpace(path, 2*size))
		require.NoError(t, reserveDiskSpace(path, size))

		info, err := os.Stat(path)
		require.NoError(t, err)
		require.Equal(t, size, info.Size())
	})

	t.Run("remove failed reservation", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "reservation")

		require.Error(t, reserveDiskSpace(path, math.MaxInt64))

		require.NoFileExists(t, path)
	})

	t.Run("keep pre-existing reservation on failed resize", func(t *testing.T) {
		const size = int64(1024 * 1024)
		path := filepath.Join(t.TempDir(), "reservation")

		require.NoError(t, reserveDiskSpace(path, size))
		require.Error(t, reserveDiskSpace(path, math.MaxInt64))

		info, err := os.Stat(path)
		require.NoError(t, err)
		require.Equal(t, size, info.Size())
	})
}

func TestGetUpgradeSize(t *testing.T) {
	t.Run("local tar.gz", func(t *testing.T) {
		archive, payload := makeGzipArtifact(t, "some artifact content")
		target := filepath.Join(t.TempDir(), "elastic-agent.tar.gz")
		require.NoError(t, os.WriteFile(target, archive, 0o644))

		archiveSize, payloadSize, err := GetLocalUpgradeSize("file://" + target)
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

		archiveSize, payloadSize, err := GetLocalUpgradeSize("file://" + target)
		require.NoError(t, err)
		require.Equal(t, uint64(len(archive)), archiveSize)
		require.Equal(t, payload, payloadSize)
	})

	t.Run("local file missing", func(t *testing.T) {
		uri := "file://" + filepath.Join(t.TempDir(), "missing.tar.gz")

		archiveSize, payloadSize, err := GetLocalUpgradeSize(uri)
		require.Error(t, err)
		require.Equal(t, FallbackArchiveSize, archiveSize)
		require.Equal(t, FallbackPayloadSize, payloadSize)
	})

	t.Run("http tar.gz", func(t *testing.T) {
		archive, payload := makeGzipArtifact(t, "some artifact content")
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.ServeContent(w, r, r.URL.Path, time.Time{}, bytes.NewReader(archive))
		}))
		t.Cleanup(server.Close)

		archiveSize, payloadSize, err := GetRemoteUpgradeSize(t.Context(), diskspaceTestConfig(t), server.URL+"/elastic-agent.tar.gz")
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

		archiveSize, payloadSize, err := GetRemoteUpgradeSize(t.Context(), diskspaceTestConfig(t), server.URL+"/elastic-agent.zip")
		require.NoError(t, err)
		require.Equal(t, uint64(len(archive)), archiveSize)
		require.Equal(t, payload, payloadSize)
	})

	t.Run("http error response", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}))
		t.Cleanup(server.Close)

		_, _, err := GetRemoteUpgradeSize(t.Context(), diskspaceTestConfig(t), server.URL+"/elastic-agent.tar.gz")
		require.Error(t, err)
	})

	t.Run("http server without range support", func(t *testing.T) {
		archive, _ := makeGzipArtifact(t, "some artifact content")
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Length", strconv.Itoa(len(archive)))
			if r.Method == http.MethodHead {
				return
			}
			// servers that don't support Range respond with 200
			_, _ = w.Write(archive)
		}))
		t.Cleanup(server.Close)

		_, _, err := GetRemoteUpgradeSize(t.Context(), diskspaceTestConfig(t), server.URL+"/elastic-agent.tar.gz")
		require.ErrorContains(t, err, "does not support range requests")
	})

	t.Run("http 416 Range Not Satisfiable", func(t *testing.T) {
		archive, _ := makeGzipArtifact(t, "some artifact content")
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodHead {
				w.Header().Set("Content-Length", strconv.Itoa(len(archive)))
				return
			}
			w.WriteHeader(http.StatusRequestedRangeNotSatisfiable)
		}))
		t.Cleanup(server.Close)

		_, _, err := GetRemoteUpgradeSize(t.Context(), diskspaceTestConfig(t), server.URL+"/elastic-agent.tar.gz")
		require.ErrorContains(t, err, "out of range")
	})

	t.Run("http missing content length", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.(http.Flusher).Flush()
		}))
		t.Cleanup(server.Close)

		_, _, err := GetRemoteUpgradeSize(t.Context(), diskspaceTestConfig(t), server.URL+"/elastic-agent.tar.gz")
		require.ErrorContains(t, err, "did not return a content length")
	})
}

func TestReserveDiskSpace(t *testing.T) {
	originalTop := paths.Top()
	paths.SetTop(t.TempDir())
	t.Cleanup(func() { paths.SetTop(originalTop) })
	require.NoError(t, os.MkdirAll(paths.Data(), 0o755))

	t.Run("reserves disk space", func(t *testing.T) {
		archive, payloadSize := makeGzipArtifact(t, "some artifact content")
		archiveDir := t.TempDir()

		hasSpace, err := ReserveDiskSpace(archiveDir, uint64(len(archive)), payloadSize)
		require.NoError(t, err)
		require.True(t, hasSpace)
		archiveReservation := getArchiveReservation(archiveDir)
		require.FileExists(t, archiveReservation)
		require.FileExists(t, getInstallReservation())

		archiveInfo, err := os.Stat(archiveReservation)
		require.NoError(t, err)
		require.Equal(t, int64(len(archive))+int64(ChecksumSize), archiveInfo.Size())
		installInfo, err := os.Stat(getInstallReservation())
		require.NoError(t, err)
		require.EqualValues(t, payloadSize+ExtraInstallSize, installInfo.Size())
	})

	t.Run("reports insufficient disk space", func(t *testing.T) {
		// mock file has 4096 entries of ~4 GiB (~16 TiB of payload content)
		archive := makeHugeZipArtifact(4096)
		target := filepath.Join(t.TempDir(), "elastic-agent.zip")
		require.NoError(t, os.WriteFile(target, archive, 0o644))
		archiveDir := t.TempDir()

		archiveSize, payloadSize, err := GetLocalUpgradeSize("file://" + target)
		require.NoError(t, err)
		hasSpace, err := ReserveDiskSpace(archiveDir, archiveSize, payloadSize)
		require.False(t, hasSpace)
		var diskSpaceErr upgradeErrors.DiskSpaceLowError
		require.ErrorAs(t, err, &diskSpaceErr)
	})
}
