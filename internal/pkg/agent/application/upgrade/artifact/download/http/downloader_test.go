// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package http

import (
	"context"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact"

	"github.com/docker/go-units"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-libs/transport/httpcommon"
)

func TestDownloadBodyError(t *testing.T) {
	// This tests the scenario where the download encounters a network error
	// part way through the download, while copying the response body.

	type connKey struct{}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		conn, ok := r.Context().Value(connKey{}).(net.Conn)
		if ok {
			_ = conn.Close()
		}
	}))
	srv.Config.ConnContext = func(ctx context.Context, c net.Conn) context.Context {
		return context.WithValue(ctx, connKey{}, c)
	}
	srv.Start()
	defer srv.Close()
	client := srv.Client()

	targetDir, err := ioutil.TempDir(os.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}

	config := &artifact.Config{
		SourceURI:       srv.URL,
		TargetDirectory: targetDir,
		OperatingSystem: "linux",
		Architecture:    "64",
	}

	log := newRecordLogger()
	testClient := NewDownloaderWithClient(log, config, *client)
	artifactPath, err := testClient.Download(context.Background(), beatSpec, version)
	os.Remove(artifactPath)
	if err == nil {
		t.Fatal("expected Download to return an error")
	}

	log.lock.RLock()
	defer log.lock.RUnlock()

	require.GreaterOrEqual(t, len(log.info), 1, "download error not logged at info level")
	assert.True(t, containsMessage(log.info, "download from %s failed at %s @ %sps: %s"))
	require.GreaterOrEqual(t, len(log.warn), 1, "download error not logged at warn level")
	assert.True(t, containsMessage(log.warn, "download from %s failed at %s @ %sps: %s"))
}

func TestDownloadLogProgressWithLength(t *testing.T) {
	fileSize := 100 * units.MB
	chunks := 100
	chunk := make([]byte, fileSize/chunks)
	delayBetweenChunks := 10 * time.Millisecond
	totalTime := time.Duration(chunks) * delayBetweenChunks

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", strconv.Itoa(fileSize))
		w.WriteHeader(http.StatusOK)
		for i := 0; i < chunks; i++ {
			_, err := w.Write(chunk)
			if err != nil {
				panic(err)
			}
			w.(http.Flusher).Flush()
			<-time.After(delayBetweenChunks)
		}
	}))
	defer srv.Close()
	client := srv.Client()

	targetDir, err := ioutil.TempDir(os.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}

	config := &artifact.Config{
		SourceURI:       srv.URL,
		TargetDirectory: targetDir,
		OperatingSystem: "linux",
		Architecture:    "64",
		HTTPTransportSettings: httpcommon.HTTPTransportSettings{
			Timeout: totalTime,
		},
	}

	log := newRecordLogger()
	testClient := NewDownloaderWithClient(log, config, *client)
	artifactPath, err := testClient.Download(context.Background(), beatSpec, version)
	os.Remove(artifactPath)
	require.NoError(t, err, "Download should not have errored")

	log.lock.RLock()
	defer log.lock.RUnlock()

	// Two files are downloaded. Each file is being downloaded in 100 chunks with a delay of 10ms between chunks. The
	// expected time to download is, therefore, 100 * 10ms = 1000ms. In reality, the actual download time will be a bit
	// more than 1000ms because some time is spent downloading the chunk, in between inter-chunk delays.
	// Reporting happens every 0.05 * 1000ms = 50ms. We expect there to be as many log messages at that INFO
	// level as the actual total download time / 50ms, for each file. That works out to at least 1000ms / 50ms = 20 log
	// messages at the INFO level for each file = 40 log messages at the INFO level for both files, about their download
	// progress. Additionally, we should expect 1 INFO message per file about the download completing. So, all in all, we
	// should expect at least 42 INFO messages.
	require.GreaterOrEqual(t, len(log.info), 42)

	// Verify that the first 20 INFO messages are about the download progress (for the first file).
	i := 0
	for ; i < 20; i++ {
		assert.Equal(t, log.info[i].record, "download progress from %s is %s/%s (%.2f%% complete) @ %sps")
	}

	// Find the next INFO message that's about the download being completed (for the first file).
	found := false
	for ; i < len(log.info) && !found; i++ {
		found = log.info[i].record == "download from %s completed in %s @ %sps"
	}
	assert.True(t, found)

	// Verify that the next 20 INFO messages are about the download progress (for the second file).
	for j := 0; j < 20; j++ {
		assert.Equal(t, log.info[i+j].record, "download progress from %s is %s/%s (%.2f%% complete) @ %sps")
	}

	// Verify that the last INFO message is about the download being completed (for the second file).
	assert.Equal(t, log.info[len(log.info)-1].record, "download from %s completed in %s @ %sps")

	// Since the download of each file is expected to take 1000ms, and the progress logger
	// starts issuing WARN messages once the download has taken more than 75% of the expected time,
	// we should see warning messages for at least the last 250 seconds of the download. Given that
	// reporting happens every 50 seconds, we should see at least 250s / 50s = 5 WARN messages
	// per file being downloaded = at least 10 WARN messages for both files about their download progress.
	// Additionally, we should expect 1 WARN message per file about the download completing. So, all in all, we
	// should expect at least 12 WARN messages.
	require.GreaterOrEqual(t, len(log.warn), 12)

	// Verify that the first 5 WARN messages are about the download progress (for the first file).
	i = 0
	for ; i < 5; i++ {
		assert.Equal(t, log.warn[i].record, "download progress from %s is %s/%s (%.2f%% complete) @ %sps")
	}

	// Find the next WARN message that's about the download being completed (for the first file).
	found = false
	for ; i < len(log.warn) && !found; i++ {
		found = log.warn[i].record == "download from %s completed in %s @ %sps"
	}
	assert.True(t, found)

	// Verify that the next 5 WARN messages are about the download progress (for the second file).
	for j := 0; j < 5; j++ {
		assert.Equal(t, log.warn[i+j].record, "download progress from %s is %s/%s (%.2f%% complete) @ %sps")
	}

	// Verify that the last WARN message is about the download being completed (for the second file).
	assert.Equal(t, log.warn[len(log.warn)-1].record, "download from %s completed in %s @ %sps")
}

func TestDownloadLogProgressWithoutLength(t *testing.T) {
	fileSize := 100 * units.MiB
	chunks := 100
	chunk := make([]byte, fileSize/chunks)
	delayBetweenChunks := 10 * time.Millisecond
	totalTime := time.Duration(chunks) * delayBetweenChunks

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		for i := 0; i < chunks; i++ {
			_, err := w.Write(chunk)
			if err != nil {
				panic(err)
			}
			w.(http.Flusher).Flush()
			<-time.After(delayBetweenChunks)
		}
	}))
	defer srv.Close()
	client := srv.Client()

	targetDir, err := ioutil.TempDir(os.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}

	config := &artifact.Config{
		SourceURI:       srv.URL,
		TargetDirectory: targetDir,
		OperatingSystem: "linux",
		Architecture:    "64",
		HTTPTransportSettings: httpcommon.HTTPTransportSettings{
			Timeout: totalTime,
		},
	}

	log := newRecordLogger()
	testClient := NewDownloaderWithClient(log, config, *client)
	artifactPath, err := testClient.Download(context.Background(), beatSpec, version)
	os.Remove(artifactPath)
	require.NoError(t, err, "Download should not have errored")

	log.lock.RLock()
	defer log.lock.RUnlock()

	// Two files are downloaded. Each file is being downloaded in 100 chunks with a delay of 10ms between chunks. The
	// expected time to download is, therefore, 100 * 10ms = 1000ms. In reality, the actual download time will be a bit
	// more than 1000ms because some time is spent downloading the chunk, in between inter-chunk delays.
	// Reporting happens every 0.05 * 1000ms = 50ms. We expect there to be as many log messages at that INFO
	// level as the actual total download time / 50ms, for each file. That works out to at least 1000ms / 50ms = 20 log
	// messages at the INFO level for each file = 40 log messages at the INFO level for both files, about their download
	// progress. Additionally, we should expect 1 INFO message per file about the download completing. So, all in all, we
	// should expect at least 42 INFO messages.
	require.GreaterOrEqual(t, len(log.info), 42)

	// Verify that the first 20 INFO messages are about the download progress (for the first file).
	i := 0
	for ; i < 20; i++ {
		assert.Equal(t, log.info[i].record, "download progress from %s has fetched %s @ %sps")
	}

	// Find the next INFO message that's about the download being completed (for the first file).
	found := false
	for ; i < len(log.info) && !found; i++ {
		found = log.info[i].record == "download from %s completed in %s @ %sps"
	}
	assert.True(t, found)

	// Verify that the next 20 INFO messages are about the download progress (for the second file).
	for j := 0; j < 20; j++ {
		assert.Equal(t, log.info[i+j].record, "download progress from %s has fetched %s @ %sps")
	}

	// Verify that the last INFO message is about the download being completed (for the second file).
	assert.Equal(t, log.info[len(log.info)-1].record, "download from %s completed in %s @ %sps")

	// Since the download of each file is expected to take 1000ms, and the progress logger
	// starts issuing WARN messages once the download has taken more than 75% of the expected time,
	// we should see warning messages for at least the last 250 seconds of the download. Given that
	// reporting happens every 50 seconds, we should see at least 250s / 50s = 5 WARN messages
	// per file being downloaded = at least 10 WARN messages for both files about their download progress.
	// Additionally, we should expect 1 WARN message per file about the download completing. So, all in all, we
	// should expect at least 12 WARN messages.
	require.GreaterOrEqual(t, len(log.warn), 12)

	// Verify that the first 5 WARN messages are about the download progress (for the first file).
	i = 0
	for ; i < 5; i++ {
		assert.Equal(t, log.warn[i].record, "download progress from %s has fetched %s @ %sps")
	}

	// Find the next WARN message that's about the download being completed (for the first file).
	found = false
	for ; i < len(log.warn) && !found; i++ {
		found = log.warn[i].record == "download from %s completed in %s @ %sps"
	}
	assert.True(t, found)

	// Verify that the next 5 WARN messages are about the download progress (for the second file).
	for j := 0; j < 5; j++ {
		assert.Equal(t, log.warn[i+j].record, "download progress from %s has fetched %s @ %sps")
	}

	// Verify that the last WARN message is about the download being completed (for the second file).
	assert.Equal(t, log.warn[len(log.warn)-1].record, "download from %s completed in %s @ %sps")
}

type logMessage struct {
	record string
	args   []interface{}
}

type recordLogger struct {
	lock sync.RWMutex
	info []logMessage
	warn []logMessage
}

func newRecordLogger() *recordLogger {
	return &recordLogger{
		info: make([]logMessage, 0, 10),
		warn: make([]logMessage, 0, 10),
	}
}

func (f *recordLogger) Infof(record string, args ...interface{}) {
	f.lock.Lock()
	defer f.lock.Unlock()
	f.info = append(f.info, logMessage{record, args})
}

func (f *recordLogger) Warnf(record string, args ...interface{}) {
	f.lock.Lock()
	defer f.lock.Unlock()
	f.warn = append(f.warn, logMessage{record, args})
}

func containsMessage(logs []logMessage, msg string) bool {
	for _, item := range logs {
		if item.record == msg {
			return true
		}
	}
	return false
}
