// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package upgrade

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
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-libs/transport/httpcommon"
	"github.com/elastic/elastic-agent-libs/transport/tlscommon"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact/download"
	downloadErrors "github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact/download/errors"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/internal/pkg/release"
	"github.com/elastic/elastic-agent/pkg/core/logger"
	"github.com/elastic/elastic-agent/pkg/core/logger/loggertest"
	"github.com/elastic/elastic-agent/pkg/upgrade/details"
	agtversion "github.com/elastic/elastic-agent/pkg/version"
)

type mockDownloader struct {
	downloadPath string
	downloadErr  error
}

func (md *mockDownloader) Download(ctx context.Context, a artifact.Artifact, filename, sourceDir, targetDir string) (string, error) {
	return md.downloadPath, md.downloadErr
}

func TestFallbackIsAppended(t *testing.T) {
	testAgentVersion123 := agtversion.NewParsedSemVer(1, 2, 3, "", "")
	testCases := []struct {
		name                 string
		passedBytes          []string
		expectedLen          int
		expectedDefaultIdx   int
		expectedSecondaryIdx int
		fleetServerURI       string
		targetVersion        *agtversion.ParsedSemVer
	}{
		{"nil input", nil, 1, 0, -1, "", testAgentVersion123},
		{"empty input", []string{}, 1, 0, -1, "", testAgentVersion123},
		{"valid input with pgp", []string{"pgp-bytes"}, 2, 1, -1, "", nil},
		{"valid input with pgp and version, no fleet uri", []string{"pgp-bytes"}, 2, 1, -1, "", testAgentVersion123},
		{"valid input with pgp and version and fleet uri", []string{"pgp-bytes"}, 3, 1, 2, "some-uri", testAgentVersion123},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			l, _ := loggertest.New(tc.name)
			a := artifactDownloader{
				fleetServerURI: tc.fleetServerURI,
				log:            l,
			}
			res := a.appendFallbackPGP(tc.targetVersion, tc.passedBytes)
			// check default fallback is passed and is very last
			require.NotNil(t, res)
			require.Equal(t, tc.expectedLen, len(res))
			require.Equal(t, download.PgpSourceURIPrefix+defaultUpgradeFallbackPGP, res[tc.expectedDefaultIdx])

			if tc.expectedSecondaryIdx >= 0 {
				// last element is fleet uri
				expectedPgpURI := download.PgpSourceURIPrefix + tc.fleetServerURI + strings.Replace(fleetUpgradeFallbackPGPFormat, "%d.%d.%d", tc.targetVersion.CoreVersion(), 1)
				require.Equal(t, expectedPgpURI, res[len(res)-1])
			}
		})
	}
}

func TestDownloadWithRetries(t *testing.T) {
	targetDir := t.TempDir()
	filename := "elastic-agent-8.9.0-linux-x86_64.tar.gz"
	sourceDir := "https://artifacts.elastic.co/downloads/beats/elastic-agent"
	expectedDownloadPath := filepath.Join(targetDir, filename)
	testLogger, obs := loggertest.New("TestDownloadWithRetries")

	settings := artifact.Config{
		RetrySleepInitDuration: 20 * time.Millisecond,
		TargetDirectory:        targetDir,
		HTTPTransportSettings: httpcommon.HTTPTransportSettings{
			Timeout: 2 * time.Second,
		},
	}

	target, err := artifact.New("elastic-agent", false, agtversion.NewParsedSemVer(8, 9, 0, "", ""), "linux", "64")
	require.NoError(t, err)

	// Successful immediately (no retries)
	t.Run("successful_immediately", func(t *testing.T) {
		mockDownloaderCtor := func(log *logger.Logger, settings *artifact.Config, upgradeDetails *details.Details) (download.Downloader, error) {
			return &mockDownloader{expectedDownloadPath, nil}, nil
		}

		a := newArtifactDownloader(&settings, testLogger)

		upgradeDetails, upgradeDetailsRetryUntil, upgradeDetailsRetryUntilWasUnset, upgradeDetailsRetryErrorMsg := mockUpgradeDetails(target.Version)
		minRetryDeadline := time.Now().Add(settings.Timeout)

		path, err := a.downloadWithRetries(context.Background(), mockDownloaderCtor, target, filename, sourceDir, targetDir, &settings, upgradeDetails)
		require.NoError(t, err)
		require.Equal(t, expectedDownloadPath, path)

		logs := obs.TakeAll()
		require.Len(t, logs, 1)
		require.Equal(t, "download attempt 1", logs[0].Message)

		// Check that upgradeDetails.Metadata.RetryUntil was set at some point
		// during the retryable download and then check that it was unset upon
		// successful download.
		require.GreaterOrEqual(t, *upgradeDetailsRetryUntil, minRetryDeadline)
		require.True(t, *upgradeDetailsRetryUntilWasUnset)
		require.Nil(t, upgradeDetails.Metadata.RetryUntil)

		// Check that upgradeDetails.Metadata.RetryErrorMsg was never set.
		require.Empty(t, *upgradeDetailsRetryErrorMsg)
	})

	// Downloader constructor failing on first attempt, but succeeding on second attempt (= first retry)
	t.Run("constructor_failure_once", func(t *testing.T) {
		attemptIdx := 0
		mockDownloaderCtor := func(log *logger.Logger, settings *artifact.Config, upgradeDetails *details.Details) (download.Downloader, error) {
			defer func() {
				attemptIdx++
			}()

			switch attemptIdx {
			case 0:
				// First attempt: fail
				return nil, errors.New("failed to construct downloader")
			case 1:
				// Second attempt: succeed
				return &mockDownloader{expectedDownloadPath, nil}, nil
			default:
				require.Fail(t, "should have succeeded after 2 attempts")
			}

			return nil, nil
		}

		a := newArtifactDownloader(&settings, testLogger)

		upgradeDetails, upgradeDetailsRetryUntil, upgradeDetailsRetryUntilWasUnset, upgradeDetailsRetryErrorMsg := mockUpgradeDetails(target.Version)
		minRetryDeadline := time.Now().Add(settings.Timeout)

		path, err := a.downloadWithRetries(context.Background(), mockDownloaderCtor, target, filename, sourceDir, targetDir, &settings, upgradeDetails)
		require.NoError(t, err)
		require.Equal(t, expectedDownloadPath, path)

		logs := obs.TakeAll()
		require.Len(t, logs, 3)
		require.Equal(t, "download attempt 1", logs[0].Message)
		require.Contains(t, logs[1].Message, "unable to create fetcher: failed to construct downloader")
		require.Equal(t, "download attempt 2", logs[2].Message)

		// Check that upgradeDetails.Metadata.RetryUntil was set at some point
		// during the retryable download and then check that it was unset upon
		// successful download.
		require.GreaterOrEqual(t, *upgradeDetailsRetryUntil, minRetryDeadline)
		require.True(t, *upgradeDetailsRetryUntilWasUnset)
		require.Nil(t, upgradeDetails.Metadata.RetryUntil)

		// Check that upgradeDetails.Metadata.RetryErrorMsg was set at some point
		// during the retryable download and then check that it was unset upon
		// successful download.
		require.NotEmpty(t, *upgradeDetailsRetryErrorMsg)
		require.Empty(t, upgradeDetails.Metadata.RetryErrorMsg)
	})

	// Download failing on first attempt, but succeeding on second attempt (= first retry)
	t.Run("download_failure_once", func(t *testing.T) {
		attemptIdx := 0
		mockDownloaderCtor := func(log *logger.Logger, settings *artifact.Config, upgradeDetails *details.Details) (download.Downloader, error) {
			defer func() {
				attemptIdx++
			}()

			switch attemptIdx {
			case 0:
				// First attempt: fail
				return &mockDownloader{"", errors.New("download failed")}, nil
			case 1:
				// Second attempt: succeed
				return &mockDownloader{expectedDownloadPath, nil}, nil
			default:
				require.Fail(t, "should have succeeded after 2 attempts")
			}

			return nil, nil
		}

		a := newArtifactDownloader(&settings, testLogger)

		upgradeDetails, upgradeDetailsRetryUntil, upgradeDetailsRetryUntilWasUnset, upgradeDetailsRetryErrorMsg := mockUpgradeDetails(target.Version)
		minRetryDeadline := time.Now().Add(settings.Timeout)

		path, err := a.downloadWithRetries(context.Background(), mockDownloaderCtor, target, filename, sourceDir, targetDir, &settings, upgradeDetails)
		require.NoError(t, err)
		require.Equal(t, expectedDownloadPath, path)

		logs := obs.TakeAll()
		require.Len(t, logs, 3)
		require.Equal(t, "download attempt 1", logs[0].Message)
		require.Contains(t, logs[1].Message, "unable to download package: download failed; retrying")
		require.Equal(t, "download attempt 2", logs[2].Message)

		// Check that upgradeDetails.Metadata.RetryUntil was set at some point
		// during the retryable download and then check that it was unset upon
		// successful download.
		require.GreaterOrEqual(t, *upgradeDetailsRetryUntil, minRetryDeadline)
		require.True(t, *upgradeDetailsRetryUntilWasUnset)
		require.Nil(t, upgradeDetails.Metadata.RetryUntil)

		// Check that upgradeDetails.Metadata.RetryErrorMsg was set at some point
		// during the retryable download and then check that it was unset upon
		// successful download.
		require.NotEmpty(t, *upgradeDetailsRetryErrorMsg)
		require.Empty(t, upgradeDetails.Metadata.RetryErrorMsg)
	})

	// Download timeout expired (before all retries are exhausted)
	t.Run("download_timeout_expired", func(t *testing.T) {
		testCaseSettings := settings
		testCaseSettings.Timeout = 500 * time.Millisecond
		testCaseSettings.RetrySleepInitDuration = 10 * time.Millisecond
		// exponential backoff with 10ms init and 500ms timeout should fit at least 3 attempts.
		minNmExpectedAttempts := 3

		mockDownloaderCtor := func(log *logger.Logger, settings *artifact.Config, upgradeDetails *details.Details) (download.Downloader, error) {
			return &mockDownloader{"", errors.New("download failed")}, nil
		}

		a := newArtifactDownloader(&settings, testLogger)

		upgradeDetails, upgradeDetailsRetryUntil, upgradeDetailsRetryUntilWasUnset, upgradeDetailsRetryErrorMsg := mockUpgradeDetails(target.Version)
		minRetryDeadline := time.Now().Add(testCaseSettings.Timeout)

		path, err := a.downloadWithRetries(context.Background(), mockDownloaderCtor, target, filename, sourceDir, targetDir, &testCaseSettings, upgradeDetails)
		require.Equal(t, "context deadline exceeded", err.Error())
		require.Equal(t, "", path)

		logs := obs.TakeAll()
		logsJSON, err := json.MarshalIndent(logs, "", " ")
		require.NoError(t, err)
		require.GreaterOrEqualf(t, len(logs), minNmExpectedAttempts*2, "logs output: %s", logsJSON)
		for i := 0; i < minNmExpectedAttempts; i++ {
			require.Equal(t, fmt.Sprintf("download attempt %d", i+1), logs[(2*i)].Message)
			require.Contains(t, logs[(2*i+1)].Message, "unable to download package: download failed; retrying")
		}

		// Check that upgradeDetails.Metadata.RetryUntil was set at some point
		// during the retryable download and then check that it was never unset,
		// since we didn't have a successful download.
		require.GreaterOrEqual(t, *upgradeDetailsRetryUntil, minRetryDeadline)
		require.False(t, *upgradeDetailsRetryUntilWasUnset)
		require.Equal(t, *upgradeDetailsRetryUntil, *upgradeDetails.Metadata.RetryUntil)

		// Check that upgradeDetails.Metadata.RetryErrorMsg was set at some point
		// during the retryable download and then check that it was never unset,
		// since we didn't have a successful download.
		require.NotEmpty(t, *upgradeDetailsRetryErrorMsg)
		require.Equal(t, *upgradeDetailsRetryErrorMsg, upgradeDetails.Metadata.RetryErrorMsg)
	})

	t.Run("insufficient disk space stops retries", func(t *testing.T) {
		numberOfAttempts := 0
		diskSpaceError := downloadErrors.OS_DiskSpaceErrors[0]
		mockDownloaderCtor := func(log *logger.Logger, settings *artifact.Config, upgradeDetails *details.Details) (download.Downloader, error) {
			numberOfAttempts++
			return &mockDownloader{"", diskSpaceError}, nil
		}

		a := newArtifactDownloader(&settings, testLogger)

		upgradeDetails, upgradeDetailsRetryUntil, upgradeDetailsRetryUntilWasUnset, upgradeDetailsRetryErrorMsg := mockUpgradeDetails(target.Version)

		path, err := a.downloadWithRetries(context.Background(), mockDownloaderCtor, target, filename, sourceDir, targetDir, &settings, upgradeDetails)

		require.Error(t, err)
		require.Equal(t, "", path)

		require.Equal(t, 1, numberOfAttempts)
		require.ErrorIs(t, err, diskSpaceError)

		require.NotZero(t, *upgradeDetailsRetryUntil)
		require.False(t, *upgradeDetailsRetryUntilWasUnset)

		require.Empty(t, *upgradeDetailsRetryErrorMsg)
	})
}

type mockVerifier struct {
	called      bool
	returnError error
}

func (mv *mockVerifier) Name() string {
	return ""
}

func (mv *mockVerifier) Verify(ctx context.Context, a artifact.Artifact, filename, sourceDir, targetDir string, skipDefaultPgp bool, pgpBytes ...string) error {
	mv.called = true
	return mv.returnError
}

func TestDownloadArtifact(t *testing.T) {
	testLogger, _ := loggertest.New("TestDownloadArtifact")
	tempConfig := &artifact.Config{} // used only to get os and arch, runtime.GOARCH returns amd64 which is not a valid arch when used to build the artifact name

	parsedVersion, err := agtversion.ParseVersion("8.9.0")
	require.NoError(t, err)

	upgradeDetails := details.NewDetails(parsedVersion.String(), details.StateRequested, "")

	mockContent := []byte("mock content")

	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, err := w.Write(mockContent)
		require.NoError(t, err)
	}))
	defer testServer.Close()

	testError := errors.New("test error")

	type testCase struct {
		mockNewVerifierFactory verifierFactory
		expectedError          error
	}

	testCases := map[string]testCase{
		"should return path if verifier constructor fails": {
			mockNewVerifierFactory: func(log *logger.Logger, settings *artifact.Config) (download.Verifier, error) {
				return nil, testError
			},
			expectedError: testError,
		},
		"should return path if verifier fails": {
			mockNewVerifierFactory: func(log *logger.Logger, settings *artifact.Config) (download.Verifier, error) {
				return &mockVerifier{returnError: testError}, nil
			},
			expectedError: testError,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			paths.SetTop(t.TempDir())

			target, err := artifact.New("elastic-agent", release.FIPSDistribution(), parsedVersion, tempConfig.OS(), tempConfig.Arch())
			require.NoError(t, err)
			artifactPath := filepath.Join(paths.Downloads(), target.FileName())

			settings := artifact.Config{
				RetrySleepInitDuration: 20 * time.Millisecond,
				HTTPTransportSettings: httpcommon.HTTPTransportSettings{
					Timeout: 2 * time.Second,
				},
				SourceURI:       testServer.URL,
				TargetDirectory: paths.Downloads(),
			}

			a := newArtifactDownloader(&settings, testLogger)
			a.newVerifier = tc.mockNewVerifierFactory

			path, err := a.downloadArtifact(t.Context(), target, testServer.URL, upgradeDetails, false, true)
			require.ErrorIs(t, err, tc.expectedError)
			require.Equal(t, artifactPath, path)
		})
	}
}

// mockUpgradeDetails returns a *details.Details value that has an observer registered on it for inspecting
// certain properties of the object being set and unset.  It also returns:
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

func TestWithFleetServerURI(t *testing.T) {
	a := &artifactDownloader{}
	a.withFleetServerURI("mockURI")
	require.Equal(t, "mockURI", a.fleetServerURI)
}

func TestResolve(t *testing.T) {
	snapshotInfo, err := os.ReadFile("./artifact/download/testdata/latest-snapshot.json")
	require.NoError(t, err)
	config := newMockResolveConfig(t, func(rw http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/latest/8.14.0-SNAPSHOT.json" {
			rw.WriteHeader(http.StatusNotFound)
			return
		}
		_, err := rw.Write(snapshotInfo)
		assert.NoError(t, err, "error writing out response body")
	})

	type args struct {
		version   *agtversion.ParsedSemVer
		sourceURI string
	}
	tests := []struct {
		name          string
		args          args
		wantFilename  string
		wantSourceDir string
		wantErr       assert.ErrorAssertionFunc
	}{
		{
			name: "empty sourceURI resolves as default",
			args: args{
				version:   agtversion.NewParsedSemVer(1, 2, 3, "", ""),
				sourceURI: "",
			},
			wantFilename:  "elastic-agent-1.2.3-linux-x86_64.tar.gz",
			wantSourceDir: "https://artifacts.elastic.co/downloads/beats/elastic-agent",
			wantErr:       assert.NoError,
		},
		{
			name: "release version with default https sourceURI",
			args: args{
				version:   agtversion.NewParsedSemVer(1, 2, 3, "", ""),
				sourceURI: artifact.DefaultSourceURI,
			},
			wantFilename:  "elastic-agent-1.2.3-linux-x86_64.tar.gz",
			wantSourceDir: "https://artifacts.elastic.co/downloads/beats/elastic-agent",
			wantErr:       assert.NoError,
		},
		{
			name: "release version (+buildID) with default https sourceURI",
			args: args{
				version:   agtversion.NewParsedSemVer(1, 2, 3, "", "build19700101"),
				sourceURI: artifact.DefaultSourceURI,
			},
			wantFilename:  "elastic-agent-1.2.3+build19700101-linux-x86_64.tar.gz",
			wantSourceDir: "https://artifacts.elastic.co/downloads/beats/elastic-agent",
			wantErr:       assert.NoError,
		},
		{
			name: "snapshot version with default https sourceURI",
			args: args{
				version:   agtversion.NewParsedSemVer(8, 14, 0, "SNAPSHOT", ""),
				sourceURI: artifact.DefaultSourceURI,
			},
			wantFilename:  "elastic-agent-8.14.0-SNAPSHOT-linux-x86_64.tar.gz",
			wantSourceDir: "https://snapshots.elastic.co/8.14.0-6d69ee76/downloads/beats/elastic-agent",
			wantErr:       assert.NoError,
		},
		{
			name: "snapshot version (+buildID) with default https sourceURI",
			args: args{
				version:   agtversion.NewParsedSemVer(8, 13, 3, "SNAPSHOT", "76ce1a63"),
				sourceURI: artifact.DefaultSourceURI,
			},
			wantFilename:  "elastic-agent-8.13.3-SNAPSHOT-linux-x86_64.tar.gz",
			wantSourceDir: "https://snapshots.elastic.co/8.13.3-76ce1a63/downloads/beats/elastic-agent",
			wantErr:       assert.NoError,
		},
		{
			name: "release version with https non-default sourceURI",
			args: args{
				version:   agtversion.NewParsedSemVer(8, 12, 0, "", ""),
				sourceURI: "https://mirror.example.com",
			},
			wantFilename:  "elastic-agent-8.12.0-linux-x86_64.tar.gz",
			wantSourceDir: "https://mirror.example.com/beats/elastic-agent",
			wantErr:       assert.NoError,
		},
		{
			name: "release version (+buildID) with https non-default sourceURI",
			args: args{
				version:   agtversion.NewParsedSemVer(8, 12, 0, "", "build19700101"),
				sourceURI: "https://mirror.example.com",
			},
			wantFilename:  "elastic-agent-8.12.0+build19700101-linux-x86_64.tar.gz",
			wantSourceDir: "https://mirror.example.com/beats/elastic-agent",
			wantErr:       assert.NoError,
		},
		{
			name: "snapshot version with https non-default sourceURI",
			args: args{
				version:   agtversion.NewParsedSemVer(8, 14, 0, "SNAPSHOT", ""),
				sourceURI: "https://mirror.example.com/downloads",
			},
			wantFilename:  "elastic-agent-8.14.0-SNAPSHOT-linux-x86_64.tar.gz",
			wantSourceDir: "https://mirror.example.com/downloads/beats/elastic-agent",
			wantErr:       assert.NoError,
		},
		{
			name: "snapshot version (+buildID) with https non-default sourceURI",
			args: args{
				version:   agtversion.NewParsedSemVer(8, 14, 0, "SNAPSHOT", "76ce1a63"),
				sourceURI: "https://mirror.example.com/downloads",
			},
			wantFilename:  "elastic-agent-8.14.0-SNAPSHOT-linux-x86_64.tar.gz",
			wantSourceDir: "https://mirror.example.com/downloads/beats/elastic-agent",
			wantErr:       assert.NoError,
		},
		{
			name: "schemeless sourceURI starting with / resolves as local",
			args: args{
				version:   agtversion.NewParsedSemVer(1, 2, 3, "", ""),
				sourceURI: "/tmp",
			},
			wantFilename:  "elastic-agent-1.2.3-linux-x86_64.tar.gz",
			wantSourceDir: "file:///tmp",
			wantErr:       assert.NoError,
		},
		{
			name: "schemeless sourceURI not starting with / resolves as https",
			args: args{
				version:   agtversion.NewParsedSemVer(1, 2, 3, "", ""),
				sourceURI: "mirror.example.com/downloads",
			},
			wantFilename:  "elastic-agent-1.2.3-linux-x86_64.tar.gz",
			wantSourceDir: "https://mirror.example.com/downloads/beats/elastic-agent",
			wantErr:       assert.NoError,
		},
		{
			name: "local snapshot file URI keeps the buildID in the file name",
			args: args{
				version:   agtversion.NewParsedSemVer(8, 14, 0, "SNAPSHOT", "76ce1a63"),
				sourceURI: "file:///tmp",
			},
			wantFilename:  "elastic-agent-8.14.0-SNAPSHOT+76ce1a63-linux-x86_64.tar.gz",
			wantSourceDir: "file:///tmp",
			wantErr:       assert.NoError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			target, err := artifact.New("elastic-agent", false, tt.args.version, "linux", "64")
			require.NoError(t, err)

			filename, sourceDir, _, err := Resolve(context.Background(), config, target, tt.args.sourceURI, "beats/elastic-agent", nil)
			if !tt.wantErr(t, err) {
				return
			}
			assert.Equal(t, tt.wantFilename, filename)
			assert.Equal(t, tt.wantSourceDir, sourceDir)
		})
	}
}

func TestResolveLatestSnapshot(t *testing.T) {
	target, err := artifact.New("elastic-agent", false, agtversion.NewParsedSemVer(8, 14, 0, "SNAPSHOT", ""), "linux", "64")
	require.NoError(t, err)

	t.Run("success", func(t *testing.T) {
		snapshotInfo, err := os.ReadFile("./artifact/download/testdata/latest-snapshot.json")
		require.NoError(t, err)
		config := newMockResolveConfig(t, func(rw http.ResponseWriter, _ *http.Request) {
			_, err := rw.Write(snapshotInfo)
			assert.NoError(t, err)
		})

		filename, sourceDir, _, err := Resolve(context.Background(), config, target, artifact.DefaultSourceURI, "beats/elastic-agent", nil)
		require.NoError(t, err)
		assert.Equal(t, "elastic-agent-8.14.0-SNAPSHOT-linux-x86_64.tar.gz", filename)
		assert.Equal(t, "https://snapshots.elastic.co/8.14.0-6d69ee76/downloads/beats/elastic-agent", sourceDir)
	})

	t.Run("failure", func(t *testing.T) {
		config := newMockResolveConfig(t, func(rw http.ResponseWriter, _ *http.Request) {
			rw.WriteHeader(http.StatusNotFound)
		})

		_, _, _, err := Resolve(context.Background(), config, target, artifact.DefaultSourceURI, "beats/elastic-agent", nil)
		require.ErrorContains(t, err, "retrieving latest snapshot build ID")
	})
}

func TestLatestSnapshotBuildID(t *testing.T) {
	version := agtversion.NewParsedSemVer(8, 14, 0, "SNAPSHOT", "")

	snapshotInfo, err := os.ReadFile("./artifact/download/testdata/latest-snapshot.json")
	require.NoError(t, err)

	t.Run("success", func(t *testing.T) {
		config := newMockResolveConfig(t, func(rw http.ResponseWriter, _ *http.Request) {
			_, err := rw.Write(snapshotInfo)
			assert.NoError(t, err)
		})

		buildID, err := latestSnapshotBuildID(context.Background(), config, version, nil)
		require.NoError(t, err)
		assert.Equal(t, "6d69ee76", buildID)
	})

	t.Run("success after one retry", func(t *testing.T) {
		requests := 0
		config := newMockResolveConfig(t, func(rw http.ResponseWriter, _ *http.Request) {
			requests++
			if requests == 1 {
				rw.WriteHeader(http.StatusInternalServerError)
				return
			}
			_, err := rw.Write(snapshotInfo)
			assert.NoError(t, err)
		})
		config.RetrySleepInitDuration = 10 * time.Millisecond

		upgradeDetails, upgradeDetailsRetryUntil, upgradeDetailsRetryUntilWasUnset, upgradeDetailsRetryErrorMsg := mockUpgradeDetails(version)

		buildID, err := latestSnapshotBuildID(context.Background(), config, version, upgradeDetails)
		require.NoError(t, err)
		assert.Equal(t, "6d69ee76", buildID)
		assert.Equal(t, 2, requests)

		// Retry details were set while retrying and cleared upon success.
		assert.NotZero(t, *upgradeDetailsRetryUntil)
		assert.True(t, *upgradeDetailsRetryUntilWasUnset)
		assert.NotEmpty(t, *upgradeDetailsRetryErrorMsg)
		assert.Nil(t, upgradeDetails.Metadata.RetryUntil)
		assert.Empty(t, upgradeDetails.Metadata.RetryErrorMsg)
	})

	t.Run("failure not found", func(t *testing.T) {
		requests := 0
		config := newMockResolveConfig(t, func(rw http.ResponseWriter, _ *http.Request) {
			requests++
			rw.WriteHeader(http.StatusNotFound)
		})

		upgradeDetails, _, _, upgradeDetailsRetryErrorMsg := mockUpgradeDetails(version)

		_, err := latestSnapshotBuildID(context.Background(), config, version, upgradeDetails)
		require.ErrorContains(t, err, "not found")

		// A 404 is a permanent error: no retries and no retryable error reported.
		assert.Equal(t, 1, requests)
		assert.Empty(t, *upgradeDetailsRetryErrorMsg)
	})

	t.Run("failure timeout", func(t *testing.T) {
		config := newMockResolveConfig(t, func(rw http.ResponseWriter, _ *http.Request) {
			rw.WriteHeader(http.StatusInternalServerError)
		})
		config.Timeout = time.Second
		config.RetrySleepInitDuration = 10 * time.Millisecond

		upgradeDetails, _, upgradeDetailsRetryUntilWasUnset, upgradeDetailsRetryErrorMsg := mockUpgradeDetails(version)

		started := time.Now()
		_, err := latestSnapshotBuildID(context.Background(), config, version, upgradeDetails)
		elapsed := time.Since(started)

		require.Error(t, err)
		assert.Less(t, elapsed, 10*time.Second)

		// Retry details remain set after exhausting the retry deadline.
		require.NotNil(t, upgradeDetails.Metadata.RetryUntil)
		assert.WithinDuration(t, started.Add(config.Timeout), *upgradeDetails.Metadata.RetryUntil, 500*time.Millisecond)
		assert.False(t, *upgradeDetailsRetryUntilWasUnset)
		assert.NotEmpty(t, *upgradeDetailsRetryErrorMsg)
	})
}

func newMockResolveConfig(t *testing.T, snapshotHandler http.HandlerFunc) *artifact.Config {
	t.Helper()

	snapshotServer := httptest.NewTLSServer(snapshotHandler)
	t.Cleanup(snapshotServer.Close)

	proxyServer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		if !assert.Equal(t, http.MethodConnect, req.Method) {
			return
		}
		upstreamConn, err := (&net.Dialer{}).DialContext(req.Context(), "tcp", snapshotServer.Listener.Addr().String())
		if !assert.NoError(t, err) {
			return
		}
		hijacker, ok := rw.(http.Hijacker)
		if !assert.True(t, ok) {
			return
		}
		clientConn, _, err := hijacker.Hijack()
		if !assert.NoError(t, err) {
			return
		}
		_, err = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
		if !assert.NoError(t, err) {
			return
		}
		go func() {
			defer upstreamConn.Close()
			defer clientConn.Close()
			_, _ = io.Copy(upstreamConn, clientConn)
		}()
		go func() {
			defer upstreamConn.Close()
			defer clientConn.Close()
			_, _ = io.Copy(clientConn, upstreamConn)
		}()
	}))
	t.Cleanup(proxyServer.Close)

	proxyURL, err := httpcommon.NewProxyURIFromString(proxyServer.URL)
	require.NoError(t, err)

	return &artifact.Config{
		HTTPTransportSettings: httpcommon.HTTPTransportSettings{
			Timeout: 10 * time.Second,
			Proxy: httpcommon.HTTPClientProxySettings{
				URL: proxyURL,
			},
			TLS: &tlscommon.Config{
				VerificationMode: tlscommon.VerifyNone,
			},
		},
	}
}
