// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package http

import (
	"context"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strconv"
	"testing"
	"time"

	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact"
	"github.com/elastic/elastic-agent/pkg/core/logger"

	"github.com/docker/go-units"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-libs/transport/httpcommon"
)

func TestDownload(t *testing.T) {
	targetDir, err := ioutil.TempDir(os.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}

	log, _ := logger.New("", false)
	timeout := 30 * time.Second
	testCases := getTestCases()
	server, _ := getElasticCoServer(t)
	elasticClient := getElasticCoClient(server)

	config := &artifact.Config{
		SourceURI:       source,
		TargetDirectory: targetDir,
		HTTPTransportSettings: httpcommon.HTTPTransportSettings{
			Timeout: timeout,
		},
	}

	for _, testCase := range testCases {
		testName := fmt.Sprintf("%s-binary-%s", testCase.system, testCase.arch)
		t.Run(testName, func(t *testing.T) {
			config.OperatingSystem = testCase.system
			config.Architecture = testCase.arch

			testClient := NewDownloaderWithClient(log, config, elasticClient)
			artifactPath, err := testClient.Download(context.Background(), beatSpec, version)
			if err != nil {
				t.Fatal(err)
			}

			_, err = os.Stat(artifactPath)
			if err != nil {
				t.Fatal(err)
			}

			os.Remove(artifactPath)
		})
	}
}

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

	log, obs := logger.NewTesting("downloader")
	testClient := NewDownloaderWithClient(log, config, *client)
	artifactPath, err := testClient.Download(context.Background(), beatSpec, version)
	os.Remove(artifactPath)
	if err == nil {
		t.Fatal("expected Download to return an error")
	}

	infoLogs := obs.FilterLevelExact(zapcore.InfoLevel).TakeAll()
	warnLogs := obs.FilterLevelExact(zapcore.WarnLevel).TakeAll()

	expectedURL := fmt.Sprintf("%s/%s-%s-%s", srv.URL, "beats/filebeat/filebeat", version, "linux-x86_64.tar.gz")
	expectedMsg := fmt.Sprintf("download from %s failed at 0B @ NaNBps: unexpected EOF", expectedURL)
	require.GreaterOrEqual(t, len(infoLogs), 1, "download error not logged at info level")
	assert.True(t, containsMessage(infoLogs, expectedMsg))
	require.GreaterOrEqual(t, len(warnLogs), 1, "download error not logged at warn level")
	assert.True(t, containsMessage(warnLogs, expectedMsg))
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

	log, obs := logger.NewTesting("downloader")
	testClient := NewDownloaderWithClient(log, config, *client)
	artifactPath, err := testClient.Download(context.Background(), beatSpec, version)
	os.Remove(artifactPath)
	require.NoError(t, err, "Download should not have errored")

	expectedURL := fmt.Sprintf("%s/%s-%s-%s", srv.URL, "beats/filebeat/filebeat", version, "linux-x86_64.tar.gz")
	expectedProgressRegexp := regexp.MustCompile(
		`^download progress from ` + expectedURL + `(.sha512)? is \S+/\S+ \(\d+\.\d{2}% complete\) @ \S+$`,
	)
	expectedCompletedRegexp := regexp.MustCompile(
		`^download from ` + expectedURL + `(.sha512)? completed in \d+ \S+ @ \S+$`,
	)

	// Consider only progress logs
	obs = obs.Filter(func(entry observer.LoggedEntry) bool {
		return expectedProgressRegexp.MatchString(entry.Message) ||
			expectedCompletedRegexp.MatchString(entry.Message)
	})

	// Two files are downloaded. Each file is being downloaded in 100 chunks with a delay of 10ms between chunks. The
	// expected time to download is, therefore, 100 * 10ms = 1000ms. In reality, the actual download time will be a bit
	// more than 1000ms because some time is spent downloading the chunk, in between inter-chunk delays.
	// Reporting happens every 0.05 * 1000ms = 50ms. We expect there to be as many log messages at that INFO level as
	// the actual total download time / 50ms, for each file. That works out to at least 1000ms / 50ms = 20 INFO log
	// messages, for each file, about its download progress. Additionally, we should expect 1 INFO log message, for
	// each file, about the download completing.
	logs := obs.FilterLevelExact(zapcore.InfoLevel).TakeAll()
	failed := assertLogs(t, logs, 20, expectedProgressRegexp, expectedCompletedRegexp)
	if failed {
		printLogs(t, logs)
	}

	// By similar math as above, since the download of each file is expected to take 1000ms, and the progress logger
	// starts issuing WARN messages once the download has taken more than 75% of the expected time,
	// we should see warning messages for at least the last 250 seconds of the download. Given that
	// reporting happens every 50 seconds, we should see at least 250s / 50s = 5 WARN log messages, for each file,
	// about its download progress. Additionally, we should expect 1 WARN message, for each file, about the download
	// completing.
	logs = obs.FilterLevelExact(zapcore.WarnLevel).TakeAll()
	failed = assertLogs(t, logs, 5, expectedProgressRegexp, expectedCompletedRegexp)
	if failed {
		printLogs(t, logs)
	}
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

	log, obs := logger.NewTesting("downloader")
	testClient := NewDownloaderWithClient(log, config, *client)
	artifactPath, err := testClient.Download(context.Background(), beatSpec, version)
	os.Remove(artifactPath)
	require.NoError(t, err, "Download should not have errored")

	expectedURL := fmt.Sprintf("%s/%s-%s-%s", srv.URL, "beats/filebeat/filebeat", version, "linux-x86_64.tar.gz")
	expectedProgressRegexp := regexp.MustCompile(
		`^download progress from ` + expectedURL + `(.sha512)? has fetched \S+ @ \S+$`,
	)
	expectedCompletedRegexp := regexp.MustCompile(
		`^download from ` + expectedURL + `(.sha512)? completed in \d+ \S+ @ \S+$`,
	)

	// Consider only progress logs
	obs = obs.Filter(func(entry observer.LoggedEntry) bool {
		return expectedProgressRegexp.MatchString(entry.Message) ||
			expectedCompletedRegexp.MatchString(entry.Message)
	})

	// Two files are downloaded. Each file is being downloaded in 100 chunks with a delay of 10ms between chunks. The
	// expected time to download is, therefore, 100 * 10ms = 1000ms. In reality, the actual download time will be a bit
	// more than 1000ms because some time is spent downloading the chunk, in between inter-chunk delays.
	// Reporting happens every 0.05 * 1000ms = 50ms. We expect there to be as many log messages at that INFO level as
	// the actual total download time / 50ms, for each file. That works out to at least 1000ms / 50ms = 20 INFO log
	// messages, for each file, about its download progress. Additionally, we should expect 1 INFO log message, for
	// each file, about the download completing.
	logs := obs.FilterLevelExact(zapcore.InfoLevel).TakeAll()
	failed := assertLogs(t, logs, 20, expectedProgressRegexp, expectedCompletedRegexp)
	if failed {
		printLogs(t, logs)
	}

	// By similar math as above, since the download of each file is expected to take 1000ms, and the progress logger
	// starts issuing WARN messages once the download has taken more than 75% of the expected time,
	// we should see warning messages for at least the last 250 seconds of the download. Given that
	// reporting happens every 50 seconds, we should see at least 250s / 50s = 5 WARN log messages, for each file,
	// about its download progress. Additionally, we should expect 1 WARN message, for each file, about the download
	// completing.
	logs = obs.FilterLevelExact(zapcore.WarnLevel).TakeAll()
	failed = assertLogs(t, logs, 5, expectedProgressRegexp, expectedCompletedRegexp)
	if failed {
		printLogs(t, logs)
	}
}

func containsMessage(logs []observer.LoggedEntry, msg string) bool {
	for _, item := range logs {
		if item.Message == msg {
			return true
		}
	}
	return false
}

func assertLogs(t *testing.T, logs []observer.LoggedEntry, minExpectedProgressLogs int, expectedProgressRegexp, expectedCompletedRegexp *regexp.Regexp) bool {
	t.Helper()

	// Verify that we've logged at least minExpectedProgressLogs (about download progress) + 1 log
	// message (about download completion), for each of the two files being downloaded.
	require.GreaterOrEqual(t, len(logs), (minExpectedProgressLogs+1)*2)

	// Verify that the first minExpectedProgressLogs messages are about the download progress (for the first file).
	i := 0
	failed := false
	for ; i < minExpectedProgressLogs; i++ {
		failed = failed || assert.Regexp(t, expectedProgressRegexp, logs[i].Message)
	}

	// Find the next message that's about the download being completed (for the first file).
	found := false
	for ; i < len(logs) && !found; i++ {
		found = expectedCompletedRegexp.MatchString(logs[i].Message)
	}
	failed = failed || assert.True(t, found)

	// Verify that the next minExpectedProgressLogs messages are about the download progress (for the second file).
	for j := 0; j < minExpectedProgressLogs; j++ {
		failed = failed || assert.Regexp(t, expectedProgressRegexp, logs[i+j].Message)
	}

	// Verify that the last message is about the download being completed (for the second file).
	failed = failed || assert.Regexp(t, expectedCompletedRegexp, logs[len(logs)-1].Message)

	return failed
}

// printLogs is called in case one of the assertions fails; it's useful for debugging
func printLogs(t *testing.T, logs []observer.LoggedEntry) {
	t.Helper()
	for _, entry := range logs {
		t.Logf("[%s] %s", entry.Level, entry.Message)
	}
}
