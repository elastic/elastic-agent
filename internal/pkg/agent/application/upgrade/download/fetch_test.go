// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package download

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"testing"
	"time"

	"github.com/docker/go-units"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/elastic/elastic-agent-libs/transport/httpcommon"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/pkg/core/logger"
	"github.com/elastic/elastic-agent/pkg/core/logger/loggertest"
	"github.com/elastic/elastic-agent/pkg/upgrade/details"
	agtversion "github.com/elastic/elastic-agent/pkg/version"
)

type downloaderTestFile struct {
	name string
	body []byte
}

type fetchTestCase struct {
	name    string
	files   []downloaderTestFile
	version *agtversion.ParsedSemVer
	want    string
	wantErr assert.ErrorAssertionFunc
}

var fetchTestCases = []fetchTestCase{
	{
		name: "happy path released version",
		files: []downloaderTestFile{
			{"elastic-agent-1.2.3-linux-x86_64.tar.gz", []byte("fake archive")},
			{"elastic-agent-1.2.3-linux-x86_64.tar.gz.sha512", []byte("somesha512 elastic-agent-1.2.3-linux-x86_64.tar.gz")},
		},
		version: agtversion.NewParsedSemVer(1, 2, 3, "", ""),
		want:    "elastic-agent-1.2.3-linux-x86_64.tar.gz",
		wantErr: assert.NoError,
	},
	{
		name: "happy path snapshot version",
		files: []downloaderTestFile{
			{"elastic-agent-1.2.3-SNAPSHOT-linux-x86_64.tar.gz", []byte("fake archive")},
			{"elastic-agent-1.2.3-SNAPSHOT-linux-x86_64.tar.gz.sha512", []byte("somesha512 elastic-agent-1.2.3-SNAPSHOT-linux-x86_64.tar.gz")},
		},
		version: agtversion.NewParsedSemVer(1, 2, 3, "SNAPSHOT", ""),
		want:    "elastic-agent-1.2.3-SNAPSHOT-linux-x86_64.tar.gz",
		wantErr: assert.NoError,
	},
	{
		name: "happy path released version with build metadata",
		files: []downloaderTestFile{
			{"elastic-agent-1.2.3+build19700101-linux-x86_64.tar.gz", []byte("fake archive")},
			{"elastic-agent-1.2.3+build19700101-linux-x86_64.tar.gz.sha512", []byte("somesha512 elastic-agent-1.2.3+build19700101-linux-x86_64.tar.gz")},
		},
		version: agtversion.NewParsedSemVer(1, 2, 3, "", "build19700101"),
		want:    "elastic-agent-1.2.3+build19700101-linux-x86_64.tar.gz",
		wantErr: assert.NoError,
	},
	{
		name: "build metadata is dropped from the snapshot version file name",
		files: []downloaderTestFile{
			{"elastic-agent-1.2.3-SNAPSHOT-linux-x86_64.tar.gz", []byte("fake archive")},
			{"elastic-agent-1.2.3-SNAPSHOT-linux-x86_64.tar.gz.sha512", []byte("somesha512 elastic-agent-1.2.3-SNAPSHOT-linux-x86_64.tar.gz")},
		},
		version: agtversion.NewParsedSemVer(1, 2, 3, "SNAPSHOT", "build19700101"),
		want:    "elastic-agent-1.2.3-SNAPSHOT-linux-x86_64.tar.gz",
		wantErr: assert.NoError,
	},
}

func TestCopy(t *testing.T) {
	for _, tt := range fetchTestCases {
		t.Run(tt.name, func(t *testing.T) {
			srcDir := t.TempDir()
			targetDir := t.TempDir()
			for _, f := range tt.files {
				dstFile := filepath.Join(srcDir, f.name)
				err := os.WriteFile(dstFile, f.body, 0o666)
				require.NoErrorf(t, err, "error preparing file %s: %v", dstFile, err)
			}

			target, err := New("elastic-agent", false, tt.version, "linux", "amd64")
			require.NoError(t, err)

			src := filepath.Join(srcDir, target.FileName)
			dst := filepath.Join(targetDir, target.FileName)
			log, _ := loggertest.New(t.Name())
			err = copy(log, src, dst, defaultFileOps())
			if !tt.wantErr(t, err, fmt.Sprintf("Copy(%v, %v)", target, src)) {
				return
			}
			if err == nil {
				assert.FileExists(t, filepath.Join(targetDir, tt.want))
			} else {
				assert.NoFileExists(t, dst)
			}
		})
	}
}

func TestDownload(t *testing.T) {
	for _, tt := range fetchTestCases {
		t.Run(tt.name, func(t *testing.T) {
			files := make(map[string][]byte, len(tt.files))
			for _, f := range tt.files {
				files["/beats/elastic-agent/"+f.name] = f.body
			}

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, ok := files[r.URL.Path]
				if !ok {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				w.WriteHeader(http.StatusOK)
				_, err := w.Write(body)
				assert.NoError(t, err)
			}))
			defer server.Close()

			target, err := New("elastic-agent", false, tt.version, "linux", "amd64")
			require.NoError(t, err)

			targetDir := t.TempDir()
			log, _ := loggertest.New(t.Name())
			upgradeDetails := details.NewDetails(tt.version.String(), details.StateRequested, "")
			config := &Config{
				TargetDirectory: targetDir,
				HTTPTransportSettings: httpcommon.HTTPTransportSettings{
					Timeout: time.Second,
				},
			}

			src := server.URL + "/beats/elastic-agent/" + target.FileName
			dst := filepath.Join(targetDir, target.FileName)
			err = download(context.Background(), log, config, upgradeDetails, nil, src, dst, defaultFileOps())
			if !tt.wantErr(t, err, fmt.Sprintf("Download(%v, %v)", target, src)) {
				return
			}
			if err == nil {
				assert.FileExists(t, filepath.Join(targetDir, tt.want))
			} else {
				assert.NoFileExists(t, dst)
			}
		})
	}
}

func TestCopyDiskSpaceError(t *testing.T) {
	testError := errors.New("test error")

	testCases := map[string]struct {
		mockStdlibFuncs func(ops *fileOps)
		expectedError   error
	}{
		"when io.Copy runs into an error, the downloader should return the error and clean up the downloaded files": {
			mockStdlibFuncs: func(ops *fileOps) {
				ops.copy = func(io.Writer, io.Reader) (int64, error) {
					return 0, testError
				}
			},
			expectedError: testError,
		},
		"when os.OpenFile runs into an error, the downloader should return the error and clean up the downloaded files": {
			mockStdlibFuncs: func(ops *fileOps) {
				ops.openFile = func(name string, flag int, perm os.FileMode) (*os.File, error) {
					return nil, testError
				}
			},
			expectedError: testError,
		},
		"when os.MkdirAll runs into an error, the downloader should return the error and clean up the downloaded files": {
			mockStdlibFuncs: func(ops *fileOps) {
				ops.mkdirAll = func(name string, perm os.FileMode) error {
					return testError
				}
			},
			expectedError: testError,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			baseDir := t.TempDir()
			paths.SetTop(baseDir)
			config := &Config{
				DropPath:        filepath.Join(baseDir, "drop"),
				TargetDirectory: filepath.Join(baseDir, "target"),
			}

			err := os.MkdirAll(config.DropPath, 0o755)
			require.NoError(t, err)

			err = os.MkdirAll(config.TargetDirectory, 0o755)
			require.NoError(t, err)

			parsedVersion := agtversion.NewParsedSemVer(1, 2, 3, "", "")

			a, err := New("elastic-agent", false, parsedVersion, runtime.GOOS, runtime.GOARCH)
			require.NoError(t, err)

			sourceArtifactPath := filepath.Join(config.DropPath, a.FileName)
			sourceArtifactHashPath := sourceArtifactPath + ".sha512"

			err = os.WriteFile(sourceArtifactPath, []byte("test"), 0o666)
			require.NoError(t, err, "failed to create source artifact file")

			err = os.WriteFile(sourceArtifactHashPath, []byte("test"), 0o666)
			require.NoError(t, err, "failed to create source artifact hash file")

			targetArtifactPath := filepath.Join(config.TargetDirectory, a.FileName)
			log, _ := loggertest.New(t.Name())

			ops := defaultFileOps()
			tc.mockStdlibFuncs(&ops)
			err = copy(log, sourceArtifactPath, targetArtifactPath, ops)

			require.ErrorIs(t, err, tc.expectedError)
			require.NoFileExists(t, targetArtifactPath)
		})
	}
}

func TestDownloadDiskSpaceError(t *testing.T) {
	targetDir, err := os.MkdirTemp(os.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}

	log, _ := loggertest.New("downloader")
	timeout := 30 * time.Second
	testCases := []struct {
		system string
		arch   string
	}{
		{system: "linux", arch: "amd64"},
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, err := w.Write([]byte("fake archive"))
		assert.NoError(t, err)
	}))
	defer server.Close()

	config := &Config{
		SourceURI:       server.URL,
		TargetDirectory: targetDir,
		HTTPTransportSettings: httpcommon.HTTPTransportSettings{
			Timeout: timeout,
		},
	}

	testError := errors.New("test error")

	type errorHandlingTestCase struct {
		mockStdlibFuncs        func(ops *fileOps)
		isDiskSpaceErrorResult bool
		expectedError          error
	}

	errorHandlingTestCases := map[string]errorHandlingTestCase{
		"when io.Copy runs into an error, the downloader should return the error and clean up the downloaded files": {
			mockStdlibFuncs: func(ops *fileOps) {
				ops.copy = func(io.Writer, io.Reader) (int64, error) {
					return 0, testError
				}
			},
			expectedError: testError,
		},
		"when io.Copy runs into disk space error, the downloader should report the error and clean up the downloaded files": {
			mockStdlibFuncs: func(ops *fileOps) {
				ops.copy = func(io.Writer, io.Reader) (int64, error) {
					return 0, testError
				}
			},
			isDiskSpaceErrorResult: true,
			expectedError:          testError,
		},
		"when os.OpenFile runs into an error, the downloader should return the error and clean up the downloaded files": {
			mockStdlibFuncs: func(ops *fileOps) {
				ops.openFile = func(name string, flag int, perm os.FileMode) (*os.File, error) {
					return nil, testError
				}
			},
			expectedError: testError,
		},
		"when os.MkdirAll runs into an error, the downloader should return the error and clean up the downloaded files": {
			mockStdlibFuncs: func(ops *fileOps) {
				ops.mkdirAll = func(name string, perm os.FileMode) error {
					return testError
				}
			},
			expectedError: testError,
		},
	}

	for _, testCase := range testCases {
		for name, etc := range errorHandlingTestCases {

			testName := fmt.Sprintf("%s-binary-%s-%s", testCase.system, testCase.arch, name)
			t.Run(testName, func(t *testing.T) {

				upgradeDetails := details.NewDetails("8.12.0", details.StateRequested, "")

				fileName := "elastic-agent-1.2.3-linux-x86_64.tar.gz"
				sourceArtifactPath := server.URL + "/" + fileName
				targetArtifactPath := filepath.Join(targetDir, fileName)
				ops := defaultFileOps()
				etc.mockStdlibFuncs(&ops)
				ops.isDiskSpaceError = func(error) bool {
					return etc.isDiskSpaceErrorResult
				}

				artifactPath := targetArtifactPath
				err := download(context.Background(), log, config, upgradeDetails, nil, sourceArtifactPath, artifactPath, ops)

				require.ErrorIs(t, err, etc.expectedError, "expected error mismatch")
				require.NoFileExists(t, artifactPath)

				if etc.isDiskSpaceErrorResult {
					require.Equal(t, details.StateFailed, upgradeDetails.State)
					require.Equal(t, ErrInsufficientDiskSpace.Error(), upgradeDetails.Metadata.ErrorMsg)
				}

				os.Remove(artifactPath)
			})
		}
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

	targetDir, err := os.MkdirTemp(os.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}

	config := &Config{
		SourceURI:       srv.URL,
		TargetDirectory: targetDir,
	}

	log, obs := loggertest.New("downloader")
	upgradeDetails := details.NewDetails("8.12.0", details.StateRequested, "")

	fileName := "elastic-agent-1.2.3-linux-x86_64.tar.gz"
	src := srv.URL + "/" + fileName
	dst := filepath.Join(targetDir, fileName)
	err = download(context.Background(), log, config, upgradeDetails, client, src, dst, defaultFileOps())
	os.Remove(dst)
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

func TestDownloadWithRetries(t *testing.T) {
	testLogger, obs := loggertest.New("TestDownloadWithRetries")
	settings := Config{
		RetrySleepInitDuration: 20 * time.Millisecond,
		HTTPTransportSettings: httpcommon.HTTPTransportSettings{
			Timeout: 2 * time.Second,
		},
	}
	parsedVersion := agtversion.NewParsedSemVer(8, 9, 0, "", "")
	target, err := New("elastic-agent", false, parsedVersion, "linux", "amd64")
	require.NoError(t, err)

	t.Run("successful_immediately", func(t *testing.T) {
		dst := filepath.Join(t.TempDir(), target.FileName)
		source := "https://example.com/" + target.FileName
		downloadOnce := func(context.Context, *logger.Logger, *Config, *details.Details, string, string) error {
			return nil
		}

		upgradeDetails, upgradeDetailsRetryUntil, upgradeDetailsRetryUntilWasUnset, upgradeDetailsRetryErrorMsg := mockUpgradeDetails(parsedVersion)
		minRetryDeadline := time.Now().Add(settings.Timeout)

		err := doWithRetries(
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

	t.Run("download_failure_once", func(t *testing.T) {
		dst := filepath.Join(t.TempDir(), target.FileName)
		source := "file://" + filepath.Join(t.TempDir(), target.FileName)
		attemptIdx := 0
		downloadOnce := func(context.Context, *logger.Logger, *Config, *details.Details, string, string) error {
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

		err := doWithRetries(
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

	t.Run("download_timeout_expired", func(t *testing.T) {
		testCaseSettings := settings
		testCaseSettings.Timeout = 500 * time.Millisecond
		testCaseSettings.RetrySleepInitDuration = 10 * time.Millisecond
		minNmExpectedAttempts := 3

		dst := filepath.Join(t.TempDir(), target.FileName)
		missingSource := "https://example.com/" + target.FileName
		downloadAlwaysFails := func(context.Context, *logger.Logger, *Config, *details.Details, string, string) error {
			return fmt.Errorf("unable to download package")
		}

		upgradeDetails, upgradeDetailsRetryUntil, upgradeDetailsRetryUntilWasUnset, upgradeDetailsRetryErrorMsg := mockUpgradeDetails(parsedVersion)
		minRetryDeadline := time.Now().Add(testCaseSettings.Timeout)

		err := doWithRetries(
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
		for i := 0; i < minNmExpectedAttempts; i++ {
			require.Equal(t, fmt.Sprintf("download attempt %d", i+1), logs[(2*i)].Message)
			require.Contains(t, logs[(2*i+1)].Message, "unable to download package")
		}

		require.GreaterOrEqual(t, *upgradeDetailsRetryUntil, minRetryDeadline)
		require.False(t, *upgradeDetailsRetryUntilWasUnset)
		require.Equal(t, *upgradeDetailsRetryUntil, *upgradeDetails.Metadata.RetryUntil)
		require.NotEmpty(t, *upgradeDetailsRetryErrorMsg)
		require.Equal(t, *upgradeDetailsRetryErrorMsg, upgradeDetails.Metadata.RetryErrorMsg)
	})

	t.Run("insufficient_disk_space_stops_retries", func(t *testing.T) {
		dst := filepath.Join(t.TempDir(), target.FileName)
		source := "https://example.com/" + target.FileName
		diskSpaceErr := fmt.Errorf("write failed: %w", OS_DiskSpaceErrors[0])
		attempts := 0
		downloadAlwaysFails := func(context.Context, *logger.Logger, *Config, *details.Details, string, string) error {
			attempts++
			return diskSpaceErr
		}

		upgradeDetails, _, _, _ := mockUpgradeDetails(parsedVersion)

		err := doWithRetries(
			context.Background(),
			testLogger,
			&settings,
			upgradeDetails,
			source,
			dst,
			downloadAlwaysFails,
		)
		require.ErrorIs(t, err, OS_DiskSpaceErrors[0])
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

	targetDir, err := os.MkdirTemp(os.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}

	config := &Config{
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
	err = download(context.Background(), log, config, upgradeDetails, client, src, dst, defaultFileOps())
	os.Remove(dst)
	require.NoError(t, err, "Download should not have errored")
	err = download(context.Background(), log, config, upgradeDetails, client, src+".sha512", dst+".sha512", defaultFileOps())
	os.Remove(dst + ".sha512")
	require.NoError(t, err, "Download should not have errored")

	expectedURL := srv.URL + "/" + fileName
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

	targetDir, err := os.MkdirTemp(os.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}

	config := &Config{
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
	err = download(context.Background(), log, config, upgradeDetails, client, src, dst, defaultFileOps())
	os.Remove(dst)
	require.NoError(t, err, "Download should not have errored")
	err = download(context.Background(), log, config, upgradeDetails, client, src+".sha512", dst+".sha512", defaultFileOps())
	os.Remove(dst + ".sha512")
	require.NoError(t, err, "Download should not have errored")

	expectedURL := srv.URL + "/" + fileName
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
