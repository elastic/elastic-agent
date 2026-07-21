// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package download

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"testing"
	"time"

	"github.com/docker/go-units"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/elastic/elastic-agent-libs/transport/httpcommon"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact"
	upgradeErrors "github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact/download/errors"
	"github.com/elastic/elastic-agent/pkg/core/logger/loggertest"
	"github.com/elastic/elastic-agent/pkg/upgrade/details"
	agtversion "github.com/elastic/elastic-agent/pkg/version"
)

var fetchCases = []struct {
	name      string
	wantError error
	ops       func() fileOps
}{
	{
		name: "success",
		ops:  defaultFileOps,
	},
	{
		name:      "copy failure",
		wantError: io.ErrUnexpectedEOF,
		ops: func() fileOps {
			ops := defaultFileOps()
			ops.copyFile = func(io.Writer, io.Reader) (int64, error) { return 0, io.ErrUnexpectedEOF }
			return ops
		},
	},
	{
		name:      "open failure",
		wantError: os.ErrPermission,
		ops: func() fileOps {
			ops := defaultFileOps()
			ops.openFile = func(string, int, os.FileMode) (*os.File, error) { return nil, os.ErrPermission }
			return ops
		},
	},
}

func TestCopy(t *testing.T) {
	for _, tc := range fetchCases {
		t.Run(tc.name, func(t *testing.T) {
			baseDir := t.TempDir()
			src := filepath.Join(baseDir, "source")
			dst := filepath.Join(baseDir, "artifact")
			require.NoError(t, os.WriteFile(src, []byte("fake archive"), 0o666))

			log, _ := loggertest.New(t.Name())
			err := copyFile(log, src, dst, tc.ops())
			if tc.wantError == nil {
				require.NoError(t, err)
				require.FileExists(t, dst)
			} else {
				require.ErrorIs(t, err, tc.wantError)
				require.NoFileExists(t, dst)
			}
		})
	}
}

func TestDownload(t *testing.T) {
	const fileName = "artifact"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, err := w.Write([]byte("fake archive"))
		assert.NoError(t, err)
	}))
	defer server.Close()

	src := server.URL + "/" + fileName
	config := &artifact.Config{
		HTTPTransportSettings: httpcommon.HTTPTransportSettings{Timeout: time.Second},
	}

	for _, tc := range fetchCases {
		t.Run(tc.name, func(t *testing.T) {
			dst := filepath.Join(t.TempDir(), fileName)
			log, _ := loggertest.New(t.Name())
			upgradeDetails := details.NewDetails("1.2.3", details.StateRequested, "")

			err := download(context.Background(), log, config, upgradeDetails, nil, src, dst, tc.ops())
			if tc.wantError == nil {
				require.NoError(t, err)
				require.FileExists(t, dst)
			} else {
				require.ErrorIs(t, err, tc.wantError)
				require.NoFileExists(t, dst)
			}
		})
	}
}

func TestCopyDiskSpaceError(t *testing.T) {
	diskSpaceError := upgradeErrors.OS_DiskSpaceErrors[0]
	baseDir := t.TempDir()
	source := filepath.Join(baseDir, "source")
	target := filepath.Join(baseDir, "artifact")
	require.NoError(t, os.WriteFile(source, []byte("fake archive"), 0o666))

	ops := defaultFileOps()
	ops.copyFile = func(io.Writer, io.Reader) (int64, error) { return 0, diskSpaceError }
	log, _ := loggertest.New(t.Name())

	err := copyFile(log, source, target, ops)
	require.ErrorIs(t, err, diskSpaceError)
	require.NoFileExists(t, target)
}

func TestDownloadDiskSpaceError(t *testing.T) {
	diskSpaceError := upgradeErrors.OS_DiskSpaceErrors[0]
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, err := w.Write([]byte("fake archive"))
		assert.NoError(t, err)
	}))
	defer server.Close()

	target := filepath.Join(t.TempDir(), "artifact")
	ops := defaultFileOps()
	ops.copyFile = func(io.Writer, io.Reader) (int64, error) { return 0, diskSpaceError }

	log, _ := loggertest.New(t.Name())
	upgradeDetails := details.NewDetails("8.12.0", details.StateRequested, "")
	config := &artifact.Config{
		HTTPTransportSettings: httpcommon.HTTPTransportSettings{Timeout: 30 * time.Second},
	}
	err := download(context.Background(), log, config, upgradeDetails, server.Client(), server.URL, target, ops)

	require.ErrorIs(t, err, diskSpaceError)
	require.NoFileExists(t, target)
	require.Equal(t, details.StateFailed, upgradeDetails.State)
	require.Equal(t, upgradeErrors.ErrInsufficientDiskSpace.Error(), upgradeDetails.Metadata.ErrorMsg)
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

	targetDir := t.TempDir()

	config := &artifact.Config{
		SourceURI:       srv.URL,
		TargetDirectory: targetDir,
	}

	log, obs := loggertest.New("downloader")
	upgradeDetails := details.NewDetails("8.12.0", details.StateRequested, "")

	fileName := "elastic-agent-1.2.3-linux-x86_64.tar.gz"
	src := srv.URL + "/" + fileName
	dst := filepath.Join(targetDir, fileName)
	err := download(context.Background(), log, config, upgradeDetails, client, src, dst, defaultFileOps())
	if err == nil {
		t.Fatal("expected Download to return an error")
	}

	infoLogs := obs.FilterLevelExact(zapcore.InfoLevel).TakeAll()
	warnLogs := obs.FilterLevelExact(zapcore.WarnLevel).TakeAll()

	expectedURL := srv.URL + "/" + fileName
	expectedMsg := fmt.Sprintf("download from %s failed at 0B @ NaNBps: unexpected EOF", expectedURL)
	require.GreaterOrEqual(t, len(infoLogs), 1, "download error not logged at info level")
	assert.True(t, containsMessage(infoLogs, expectedMsg))
	require.GreaterOrEqual(t, len(warnLogs), 1, "download error not logged at warn level")
	assert.True(t, containsMessage(warnLogs, expectedMsg))
}

func containsMessage(logs []observer.LoggedEntry, msg string) bool {
	for _, item := range logs {
		if item.Message == msg {
			return true
		}
	}
	return false
}

func TestDownloadWithRetries(t *testing.T) {
	testLogger, obs := loggertest.New("TestDownloadWithRetries")
	settings := artifact.Config{
		RetrySleepInitDuration: 20 * time.Millisecond,
		HTTPTransportSettings: httpcommon.HTTPTransportSettings{
			Timeout: 2 * time.Second,
		},
	}
	parsedVersion := agtversion.NewParsedSemVer(8, 9, 0, "", "")
	target, err := artifact.New("elastic-agent", false, parsedVersion, "linux", "amd64")
	require.NoError(t, err)

	t.Run("initial success", func(t *testing.T) {
		dst := filepath.Join(t.TempDir(), target.FileName())
		source := "https://example.com/" + target.FileName()
		downloadOnce := func(context.Context, string, string) error {
			return nil
		}

		upgradeDetails, upgradeDetailsRetryUntil, upgradeDetailsRetryUntilWasUnset, upgradeDetailsRetryErrorMsg := mockUpgradeDetails(parsedVersion)
		minRetryDeadline := time.Now().Add(settings.Timeout)

		err := downloadWithRetries(
			context.Background(),
			testLogger,
			&settings,
			upgradeDetails,
			source,
			dst,
			downloadOnce,
		)
		require.NoError(t, err)

		logs := obs.TakeAll()
		require.Len(t, logs, 1)
		require.Equal(t, "download attempt 1", logs[0].Message)
		require.GreaterOrEqual(t, *upgradeDetailsRetryUntil, minRetryDeadline)
		require.True(t, *upgradeDetailsRetryUntilWasUnset)
		require.Nil(t, upgradeDetails.Metadata.RetryUntil)
		require.Empty(t, *upgradeDetailsRetryErrorMsg)
	})

	t.Run("download fails once", func(t *testing.T) {
		dst := filepath.Join(t.TempDir(), target.FileName())
		source := "file://" + filepath.Join(t.TempDir(), target.FileName())
		attemptIdx := 0
		downloadOnce := func(context.Context, string, string) error {
			defer func() {
				attemptIdx++
			}()

			switch attemptIdx {
			case 0:
				return fmt.Errorf("download failed")
			case 1:
				return nil
			default:
				require.Fail(t, "should have succeeded after 2 attempts")
			}

			return nil
		}

		upgradeDetails, upgradeDetailsRetryUntil, upgradeDetailsRetryUntilWasUnset, upgradeDetailsRetryErrorMsg := mockUpgradeDetails(parsedVersion)
		minRetryDeadline := time.Now().Add(settings.Timeout)

		err := downloadWithRetries(
			context.Background(),
			testLogger,
			&settings,
			upgradeDetails,
			source,
			dst,
			downloadOnce,
		)
		require.NoError(t, err)

		logs := obs.TakeAll()
		require.Len(t, logs, 3)
		require.Equal(t, "download attempt 1", logs[0].Message)
		require.Contains(t, logs[1].Message, "download failed; retrying")
		require.Equal(t, "download attempt 2", logs[2].Message)
		require.GreaterOrEqual(t, *upgradeDetailsRetryUntil, minRetryDeadline)
		require.True(t, *upgradeDetailsRetryUntilWasUnset)
		require.Nil(t, upgradeDetails.Metadata.RetryUntil)
		require.NotEmpty(t, *upgradeDetailsRetryErrorMsg)
		require.Empty(t, upgradeDetails.Metadata.RetryErrorMsg)
	})

	t.Run("download timeout expired", func(t *testing.T) {
		testCaseSettings := settings
		testCaseSettings.Timeout = 500 * time.Millisecond
		testCaseSettings.RetrySleepInitDuration = 10 * time.Millisecond
		minNmExpectedAttempts := 3

		dst := filepath.Join(t.TempDir(), target.FileName())
		missingSource := "https://example.com/" + target.FileName()
		downloadAlwaysFails := func(context.Context, string, string) error {
			return fmt.Errorf("unable to download package")
		}

		upgradeDetails, upgradeDetailsRetryUntil, upgradeDetailsRetryUntilWasUnset, upgradeDetailsRetryErrorMsg := mockUpgradeDetails(parsedVersion)
		minRetryDeadline := time.Now().Add(testCaseSettings.Timeout)

		err := downloadWithRetries(
			context.Background(),
			testLogger,
			&testCaseSettings,
			upgradeDetails,
			missingSource,
			dst,
			downloadAlwaysFails,
		)
		require.Equal(t, "context deadline exceeded", err.Error())

		logs := obs.TakeAll()
		logsJSON, err := json.MarshalIndent(logs, "", " ")
		require.NoError(t, err)
		require.GreaterOrEqualf(t, len(logs), minNmExpectedAttempts*2, "logs output: %s", logsJSON)
		for i := range minNmExpectedAttempts {
			require.Equal(t, fmt.Sprintf("download attempt %d", i+1), logs[(2*i)].Message)
			require.Contains(t, logs[(2*i+1)].Message, "unable to download package")
		}

		require.GreaterOrEqual(t, *upgradeDetailsRetryUntil, minRetryDeadline)
		require.False(t, *upgradeDetailsRetryUntilWasUnset)
		require.Equal(t, *upgradeDetailsRetryUntil, *upgradeDetails.Metadata.RetryUntil)
		require.NotEmpty(t, *upgradeDetailsRetryErrorMsg)
		require.Equal(t, *upgradeDetailsRetryErrorMsg, upgradeDetails.Metadata.RetryErrorMsg)
	})

	t.Run("permanent HTTP statuses stop retries", func(t *testing.T) {
		for _, statusCode := range []int{
			http.StatusBadRequest,
			http.StatusUnauthorized,
			http.StatusForbidden,
			http.StatusNotFound,
			http.StatusGone,
		} {
			t.Run(http.StatusText(statusCode), func(t *testing.T) {
				attempts := 0
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					attempts++
					w.WriteHeader(statusCode)
				}))
				defer server.Close()

				log, _ := loggertest.New(t.Name())
				err := downloadWithRetries(context.Background(), log, &settings,
					details.NewDetails(parsedVersion.String(), details.StateRequested, ""), server.URL,
					filepath.Join(t.TempDir(), target.FileName()),
					func(ctx context.Context, source, dst string) error {
						return download(ctx, log, &settings,
							details.NewDetails(parsedVersion.String(), details.StateRequested, ""),
							server.Client(), source, dst, defaultFileOps())
					})
				require.ErrorIs(t, err, upgradeErrors.ErrPermanentHTTP)
				require.Equal(t, 1, attempts)
			})
		}
	})

	t.Run("insufficient diskspace stops retries", func(t *testing.T) {
		dst := filepath.Join(t.TempDir(), target.FileName())
		source := "https://example.com/" + target.FileName()
		diskSpaceErr := fmt.Errorf("write failed: %w", upgradeErrors.OS_DiskSpaceErrors[0])
		attempts := 0
		downloadAlwaysFails := func(context.Context, string, string) error {
			attempts++
			return diskSpaceErr
		}

		upgradeDetails, _, _, _ := mockUpgradeDetails(parsedVersion)

		err := downloadWithRetries(
			context.Background(),
			testLogger,
			&settings,
			upgradeDetails,
			source,
			dst,
			downloadAlwaysFails,
		)
		require.ErrorIs(t, err, upgradeErrors.OS_DiskSpaceErrors[0])
		require.Equal(t, 1, attempts)

		logs := obs.TakeAll()
		require.Len(t, logs, 2)
		require.Equal(t, "download attempt 1", logs[0].Message)
		require.Contains(t, logs[1].Message, "insufficient disk space error detected, stopping retries")
	})
}

// mockUpgradeDetails returns a *details.Details value that has an observer registered on it for inspecting
// certain properties of the object being set and unset. It also returns:
// - a *time.Time value, which will be not nil if Metadata.RetryUntil is set on the mock value,
// - a *bool value, which will be true if Metadata.RetryUntil is set and then unset on the mock value,
// - a *string value, which will be non-empty if Metadata.RetryErrorMsg is set on the mock value.
func mockUpgradeDetails(parsedVersion *agtversion.ParsedSemVer) (*details.Details, *time.Time, *bool, *string) {
	var upgradeDetailsRetryUntil time.Time
	var upgradeDetailsRetryUntilWasUnset bool
	var upgradeDetailsRetryErrorMsg string

	upgradeDetails := details.NewDetails(parsedVersion.String(), details.StateRequested, "")
	upgradeDetails.RegisterObserver(func(details *details.Details) {
		if details.Metadata.RetryUntil != nil {
			upgradeDetailsRetryUntil = *details.Metadata.RetryUntil
		}

		if !upgradeDetailsRetryUntil.IsZero() && details.Metadata.RetryUntil == nil {
			upgradeDetailsRetryUntilWasUnset = true
		}

		if details.Metadata.RetryErrorMsg != "" {
			upgradeDetailsRetryErrorMsg = details.Metadata.RetryErrorMsg
		}
	})

	return upgradeDetails,
		&upgradeDetailsRetryUntil, &upgradeDetailsRetryUntilWasUnset,
		&upgradeDetailsRetryErrorMsg
}

func TestDownloadLogProgress(t *testing.T) {
	chunks := 100
	delayBetweenChunks := 10 * time.Millisecond
	totalTime := time.Duration(chunks) * delayBetweenChunks

	testCases := []struct {
		name          string
		fileSize      int
		sendLength    bool
		progressRegex string
	}{
		{
			name:          "with length",
			fileSize:      100 * units.MB,
			sendLength:    true,
			progressRegex: `is \S+/\S+ \(\d+\.\d{2}% complete\) @ \S+`,
		},
		{
			name:          "without length",
			fileSize:      100 * units.MiB,
			sendLength:    false,
			progressRegex: `has fetched \S+ @ \S+`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			chunk := make([]byte, tc.fileSize/chunks)

			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tc.sendLength {
					w.Header().Set("Content-Length", strconv.Itoa(tc.fileSize))
				}
				w.WriteHeader(http.StatusOK)
				for range chunks {
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

			targetDir := t.TempDir()

			config := &artifact.Config{
				SourceURI:       srv.URL,
				TargetDirectory: targetDir,
				HTTPTransportSettings: httpcommon.HTTPTransportSettings{
					Timeout: totalTime,
				},
			}

			log, obs := loggertest.New("downloader")
			upgradeDetails := details.NewDetails("8.12.0", details.StateRequested, "")
			fileName := "elastic-agent-1.2.3-linux-x86_64.tar.gz"
			src := srv.URL + "/" + fileName
			dst := filepath.Join(targetDir, fileName)
			err := download(context.Background(), log, config, upgradeDetails, client, src, dst, defaultFileOps())
			require.NoError(t, err, "Download should not have errored")
			err = download(context.Background(), log, config, upgradeDetails, client, src+".sha512", dst+".sha512", defaultFileOps())
			require.NoError(t, err, "Download should not have errored")

			expectedURL := srv.URL + "/" + fileName
			expectedProgressRegexp := regexp.MustCompile(
				`^download progress from ` + expectedURL + `(.sha512)? ` + tc.progressRegex + `$`,
			)
			expectedCompletedRegexp := regexp.MustCompile(
				`^download from ` + expectedURL + `(.sha512)? completed in \d+ \S+ @ \S+$`,
			)

			// Consider only progress logs
			obs = obs.Filter(func(entry observer.LoggedEntry) bool {
				return expectedProgressRegexp.MatchString(entry.Message) ||
					expectedCompletedRegexp.MatchString(entry.Message)
			})

			logChecks := []struct {
				level                   zapcore.Level
				minExpectedProgressLogs int
			}{
				// Each download takes at least 100 * 10ms = 1000ms. Progress is reported every 5%: 0.05 * 1000ms = 50ms.
				// 1000ms / 50ms = 20 INFO progress logs + 1 completion log
				{level: zapcore.InfoLevel, minExpectedProgressLogs: 20},
				// WARN progress starts after 75% of the timeout, leaving 1000ms - 750ms = 250ms.
				// 250ms / 50ms = 5 WARN progress logs and one additional WARN completion log per file.
				{level: zapcore.WarnLevel, minExpectedProgressLogs: 5},
			}
			for _, check := range logChecks {
				logs := obs.FilterLevelExact(check.level).TakeAll()
				if assertLogs(t, logs, check.minExpectedProgressLogs, expectedProgressRegexp, expectedCompletedRegexp) {
					for _, entry := range logs {
						t.Logf("[%s] %s", entry.Level, entry.Message)
					}
				}
			}
		})
	}
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
	for j := range minExpectedProgressLogs {
		failed = failed || assert.Regexp(t, expectedProgressRegexp, logs[i+j].Message)
	}

	// Verify that the last message is about the download being completed (for the second file).
	failed = failed || assert.Regexp(t, expectedCompletedRegexp, logs[len(logs)-1].Message)

	return failed
}
