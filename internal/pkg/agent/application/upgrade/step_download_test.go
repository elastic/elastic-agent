// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package upgrade

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-libs/transport/httpcommon"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact/download"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/details"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/pkg/core/logger"
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
	testCases := []struct {
		name                 string
		passedBytes          []string
		expectedLen          int
		expectedDefaultIdx   int
		expectedSecondaryIdx int
		fleetServerURI       string
		targetVersion        string
	}{
		{"nil input", nil, 1, 0, -1, "", ""},
		{"empty input", []string{}, 1, 0, -1, "", ""},
		{"valid input with pgp", []string{"pgp-bytes"}, 2, 1, -1, "", ""},
		{"valid input with pgp and version, no fleet uri", []string{"pgp-bytes"}, 2, 1, -1, "", "1.2.3"},
		{"valid input with pgp and version and fleet uri", []string{"pgp-bytes"}, 3, 1, 2, "some-uri", "1.2.3"},
		{"valid input with pgp and fleet uri no version", []string{"pgp-bytes"}, 2, 1, -1, "some-uri", ""},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			l, _ := logger.NewTesting(tc.name)
			u := Upgrader{
				fleetServerURI: tc.fleetServerURI,
				log:            l,
			}
			res := u.appendFallbackPGP(tc.targetVersion, tc.passedBytes)
			// check default fallback is passed and is very last
			require.NotNil(t, res)
			require.Equal(t, tc.expectedLen, len(res))
			require.Equal(t, download.PgpSourceURIPrefix+defaultUpgradeFallbackPGP, res[tc.expectedDefaultIdx])

			if tc.expectedSecondaryIdx >= 0 {
				// last element is fleet uri
				expectedPgpURI := download.PgpSourceURIPrefix + tc.fleetServerURI + strings.Replace(fleetUpgradeFallbackPGPFormat, "%d.%d.%d", tc.targetVersion, 1)
				require.Equal(t, expectedPgpURI, res[len(res)-1])
			}
		})
	}
}

func TestDownloadWithRetries(t *testing.T) {
	expectedDownloadPath := "https://artifacts.elastic.co/downloads/beats/elastic-agent"
	testLogger, obs := logger.NewTesting("TestDownloadWithRetries")

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

		u, err := NewUpgrader(testLogger, &settings, &info.AgentInfo{})
		require.NoError(t, err)

		parsedVersion, err := agtversion.ParseVersion("8.9.0")
		require.NoError(t, err)

		upgradeDetails, upgradeDetailsRetryUntil, upgradeDetailsRetryUntilWasUnset, upgradeDetailsRetryErrorMsg := mockUpgradeDetails(parsedVersion)
		minRetryDeadline := time.Now().Add(settings.Timeout)

		path, err := u.downloadWithRetries(context.Background(), mockDownloaderCtor, parsedVersion, &settings, upgradeDetails)
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

		u, err := NewUpgrader(testLogger, &settings, &info.AgentInfo{})
		require.NoError(t, err)

		parsedVersion, err := agtversion.ParseVersion("8.9.0")
		require.NoError(t, err)

		upgradeDetails, upgradeDetailsRetryUntil, upgradeDetailsRetryUntilWasUnset, upgradeDetailsRetryErrorMsg := mockUpgradeDetails(parsedVersion)
		minRetryDeadline := time.Now().Add(settings.Timeout)

		path, err := u.downloadWithRetries(context.Background(), mockDownloaderCtor, parsedVersion, &settings, upgradeDetails)
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

		u, err := NewUpgrader(testLogger, &settings, &info.AgentInfo{})
		require.NoError(t, err)

		parsedVersion, err := agtversion.ParseVersion("8.9.0")
		require.NoError(t, err)

		upgradeDetails, upgradeDetailsRetryUntil, upgradeDetailsRetryUntilWasUnset, upgradeDetailsRetryErrorMsg := mockUpgradeDetails(parsedVersion)
		minRetryDeadline := time.Now().Add(settings.Timeout)

		path, err := u.downloadWithRetries(context.Background(), mockDownloaderCtor, parsedVersion, &settings, upgradeDetails)
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
		testCaseSettings.Timeout = 200 * time.Millisecond
		testCaseSettings.RetrySleepInitDuration = 100 * time.Millisecond

		mockDownloaderCtor := func(version *agtversion.ParsedSemVer, log *logger.Logger, settings *artifact.Config, upgradeDetails *details.Details) (download.Downloader, error) {
			return &mockDownloader{"", errors.New("download failed")}, nil
		}

		u, err := NewUpgrader(testLogger, &settings, &info.AgentInfo{})
		require.NoError(t, err)

		parsedVersion, err := agtversion.ParseVersion("8.9.0")
		require.NoError(t, err)

		upgradeDetails, upgradeDetailsRetryUntil, upgradeDetailsRetryUntilWasUnset, upgradeDetailsRetryErrorMsg := mockUpgradeDetails(parsedVersion)
		minRetryDeadline := time.Now().Add(testCaseSettings.Timeout)

		path, err := u.downloadWithRetries(context.Background(), mockDownloaderCtor, parsedVersion, &testCaseSettings, upgradeDetails)
		require.Equal(t, "context deadline exceeded", err.Error())
		require.Equal(t, "", path)

		minNmExpectedAttempts := int(testCaseSettings.Timeout / testCaseSettings.RetrySleepInitDuration)
		logs := obs.TakeAll()
		require.GreaterOrEqual(t, len(logs), minNmExpectedAttempts*2)
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
		//since we didn't have a successful download.
		require.NotEmpty(t, *upgradeDetailsRetryErrorMsg)
		require.Equal(t, *upgradeDetailsRetryErrorMsg, upgradeDetails.Metadata.RetryErrorMsg)
	})
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
