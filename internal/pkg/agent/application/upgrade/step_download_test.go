// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package upgrade

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-libs/transport/httpcommon"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact/download"
	downloadErrors "github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact/download/errors"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/details"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/pkg/core/logger"
	"github.com/elastic/elastic-agent/pkg/core/logger/loggertest"
	agtversion "github.com/elastic/elastic-agent/pkg/version"
)

type mockDownloader struct {
	downloadPath string
	downloadErr  error
}

func (md *mockDownloader) Download(ctx context.Context, a artifact.Artifact, version *agtversion.ParsedSemVer) (string, error) {
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
	expectedDownloadPath := "https://artifacts.elastic.co/downloads/beats/elastic-agent"
	testLogger, obs := loggertest.New("TestDownloadWithRetries")

	settings := artifact.Config{
		RetrySleepInitDuration: 20 * time.Millisecond,
		HTTPTransportSettings: httpcommon.HTTPTransportSettings{
			Timeout: 2 * time.Second,
		},
	}

	// Successful immediately (no retries)
	t.Run("successful_immediately", func(t *testing.T) {
		mockDownloaderCtor := func(version *agtversion.ParsedSemVer, log *logger.Logger, settings *artifact.Config, upgradeDetails *details.Details) (download.Downloader, error) {
			return &mockDownloader{expectedDownloadPath, nil}, nil
		}

		a := newArtifactDownloader(&settings, testLogger)

		parsedVersion, err := agtversion.ParseVersion("8.9.0")
		require.NoError(t, err)

		upgradeDetails, upgradeDetailsRetryUntil, upgradeDetailsRetryUntilWasUnset, upgradeDetailsRetryErrorMsg := mockUpgradeDetails(parsedVersion)
		minRetryDeadline := time.Now().Add(settings.Timeout)

		path, err := a.downloadWithRetries(context.Background(), mockDownloaderCtor, parsedVersion, &settings, upgradeDetails)
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
		mockDownloaderCtor := func(version *agtversion.ParsedSemVer, log *logger.Logger, settings *artifact.Config, upgradeDetails *details.Details) (download.Downloader, error) {
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

		parsedVersion, err := agtversion.ParseVersion("8.9.0")
		require.NoError(t, err)

		upgradeDetails, upgradeDetailsRetryUntil, upgradeDetailsRetryUntilWasUnset, upgradeDetailsRetryErrorMsg := mockUpgradeDetails(parsedVersion)
		minRetryDeadline := time.Now().Add(settings.Timeout)

		path, err := a.downloadWithRetries(context.Background(), mockDownloaderCtor, parsedVersion, &settings, upgradeDetails)
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
		mockDownloaderCtor := func(version *agtversion.ParsedSemVer, log *logger.Logger, settings *artifact.Config, upgradeDetails *details.Details) (download.Downloader, error) {
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

		parsedVersion, err := agtversion.ParseVersion("8.9.0")
		require.NoError(t, err)

		upgradeDetails, upgradeDetailsRetryUntil, upgradeDetailsRetryUntilWasUnset, upgradeDetailsRetryErrorMsg := mockUpgradeDetails(parsedVersion)
		minRetryDeadline := time.Now().Add(settings.Timeout)

		path, err := a.downloadWithRetries(context.Background(), mockDownloaderCtor, parsedVersion, &settings, upgradeDetails)
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

		mockDownloaderCtor := func(version *agtversion.ParsedSemVer, log *logger.Logger, settings *artifact.Config, upgradeDetails *details.Details) (download.Downloader, error) {
			return &mockDownloader{"", errors.New("download failed")}, nil
		}

		a := newArtifactDownloader(&settings, testLogger)

		parsedVersion, err := agtversion.ParseVersion("8.9.0")
		require.NoError(t, err)

		upgradeDetails, upgradeDetailsRetryUntil, upgradeDetailsRetryUntilWasUnset, upgradeDetailsRetryErrorMsg := mockUpgradeDetails(parsedVersion)
		minRetryDeadline := time.Now().Add(testCaseSettings.Timeout)

		path, err := a.downloadWithRetries(context.Background(), mockDownloaderCtor, parsedVersion, &testCaseSettings, upgradeDetails)
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
		mockDownloaderCtor := func(version *agtversion.ParsedSemVer, log *logger.Logger, settings *artifact.Config, upgradeDetails *details.Details) (download.Downloader, error) {
			numberOfAttempts++
			return &mockDownloader{"", diskSpaceError}, nil
		}

		a := newArtifactDownloader(&settings, testLogger)

		parsedVersion, err := agtversion.ParseVersion("8.9.0")
		require.NoError(t, err)

		upgradeDetails, upgradeDetailsRetryUntil, upgradeDetailsRetryUntilWasUnset, upgradeDetailsRetryErrorMsg := mockUpgradeDetails(parsedVersion)

		path, err := a.downloadWithRetries(context.Background(), mockDownloaderCtor, parsedVersion, &settings, upgradeDetails)

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

func (mv *mockVerifier) Verify(ctx context.Context, a artifact.Artifact, version agtversion.ParsedSemVer, skipDefaultPgp bool, pgpBytes ...string) error {
	mv.called = true
	return mv.returnError
}

func TestDownloadArtifact(t *testing.T) {
	testLogger, _ := loggertest.New("TestDownloadArtifact")
	tempConfig := &artifact.Config{} // used only to get os and arch, runtime.GOARCH returns amd64 which is not a valid arch when used in GetArtifactName

	parsedVersion, err := agtversion.ParseVersion("8.9.0")
	require.NoError(t, err)

	upgradeDeatils := details.NewDetails(parsedVersion.String(), details.StateRequested, "")

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
			mockNewVerifierFactory: func(version *agtversion.ParsedSemVer, log *logger.Logger, settings *artifact.Config) (download.Verifier, error) {
				return nil, testError
			},
			expectedError: testError,
		},
		"should return path if verifier fails": {
			mockNewVerifierFactory: func(version *agtversion.ParsedSemVer, log *logger.Logger, settings *artifact.Config) (download.Verifier, error) {
				return &mockVerifier{returnError: testError}, nil
			},
			expectedError: testError,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			paths.SetTop(t.TempDir())

			artifactPath, err := artifact.GetArtifactPath(agentArtifact, *parsedVersion, tempConfig.OS(), tempConfig.Arch(), paths.Downloads())
			require.NoError(t, err)

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

			path, err := a.downloadArtifact(t.Context(), parsedVersion, testServer.URL, upgradeDeatils, false, true)
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
