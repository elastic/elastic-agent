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
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/pkg/core/logger"
	agtversion "github.com/elastic/elastic-agent/pkg/version"
)

type mockDownloader struct {
	downloadPath string
	downloadErr  error
}

func (md *mockDownloader) Download(ctx context.Context, agentArtifact artifact.Artifact, version string) (string, error) {
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
		mockDownloaderCtor := func(version *agtversion.ParsedSemVer, log *logger.Logger, settings *artifact.Config) (download.Downloader, error) {
			return &mockDownloader{expectedDownloadPath, nil}, nil
		}

		u := NewUpgrader(testLogger, &settings, &info.AgentInfo{})
		parsedVersion, err := agtversion.ParseVersion("8.9.0")
		require.NoError(t, err)
		path, err := u.downloadWithRetries(context.Background(), mockDownloaderCtor, parsedVersion, &settings)
		require.NoError(t, err)
		require.Equal(t, expectedDownloadPath, path)

		logs := obs.TakeAll()
		require.Len(t, logs, 1)
		require.Equal(t, "download attempt 1", logs[0].Message)
	})

	// Downloader constructor failing on first attempt, but succeeding on second attempt (= first retry)
	t.Run("constructor_failure_once", func(t *testing.T) {
		attemptIdx := 0
		mockDownloaderCtor := func(version *agtversion.ParsedSemVer, log *logger.Logger, settings *artifact.Config) (download.Downloader, error) {
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

		u := NewUpgrader(testLogger, &settings, &info.AgentInfo{})
		parsedVersion, err := agtversion.ParseVersion("8.9.0")
		require.NoError(t, err)
		path, err := u.downloadWithRetries(context.Background(), mockDownloaderCtor, parsedVersion, &settings)
		require.NoError(t, err)
		require.Equal(t, expectedDownloadPath, path)

		logs := obs.TakeAll()
		require.Len(t, logs, 3)
		require.Equal(t, "download attempt 1", logs[0].Message)
		require.Contains(t, logs[1].Message, "unable to create fetcher: failed to construct downloader; retrying (will be retry 1)")
		require.Equal(t, "download attempt 2", logs[2].Message)
	})

	// Download failing on first attempt, but succeeding on second attempt (= first retry)
	t.Run("download_failure_once", func(t *testing.T) {
		attemptIdx := 0
		mockDownloaderCtor := func(version *agtversion.ParsedSemVer, log *logger.Logger, settings *artifact.Config) (download.Downloader, error) {
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

		u := NewUpgrader(testLogger, &settings, &info.AgentInfo{})
		parsedVersion, err := agtversion.ParseVersion("8.9.0")
		require.NoError(t, err)
		path, err := u.downloadWithRetries(context.Background(), mockDownloaderCtor, parsedVersion, &settings)
		require.NoError(t, err)
		require.Equal(t, expectedDownloadPath, path)

		logs := obs.TakeAll()
		require.Len(t, logs, 3)
		require.Equal(t, "download attempt 1", logs[0].Message)
		require.Contains(t, logs[1].Message, "unable to download package: download failed; retrying (will be retry 1)")
		require.Equal(t, "download attempt 2", logs[2].Message)
	})

	// Download timeout expired (before all retries are exhausted)
	t.Run("download_timeout_expired", func(t *testing.T) {
		testCaseSettings := settings
		testCaseSettings.Timeout = 200 * time.Millisecond
		testCaseSettings.RetrySleepInitDuration = 100 * time.Millisecond

		mockDownloaderCtor := func(version *agtversion.ParsedSemVer, log *logger.Logger, settings *artifact.Config) (download.Downloader, error) {
			return &mockDownloader{"", errors.New("download failed")}, nil
		}

		u := NewUpgrader(testLogger, &settings, &info.AgentInfo{})
		parsedVersion, err := agtversion.ParseVersion("8.9.0")
		require.NoError(t, err)
		path, err := u.downloadWithRetries(context.Background(), mockDownloaderCtor, parsedVersion, &testCaseSettings)
		require.Equal(t, "context deadline exceeded", err.Error())
		require.Equal(t, "", path)

		minNmExpectedAttempts := int(testCaseSettings.Timeout / testCaseSettings.RetrySleepInitDuration)
		logs := obs.TakeAll()
		require.GreaterOrEqual(t, len(logs), minNmExpectedAttempts*2)
		for i := 0; i < minNmExpectedAttempts; i++ {
			require.Equal(t, fmt.Sprintf("download attempt %d", i+1), logs[(2*i)].Message)
			require.Contains(t, logs[(2*i+1)].Message, fmt.Sprintf("unable to download package: download failed; retrying (will be retry %d)", i+1))
		}
	})
}
