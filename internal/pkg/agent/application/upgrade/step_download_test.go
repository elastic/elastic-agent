package upgrade

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"

	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"

	"github.com/elastic/elastic-agent-libs/transport/httpcommon"

	"github.com/elastic/elastic-agent/pkg/core/logger"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact/download"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact"
)

type mockDownloader struct {
	downloadPath string
	downloadErr  error
}

func (md *mockDownloader) Download(ctx context.Context, agentArtifact artifact.Artifact, version string) (string, error) {
	return md.downloadPath, md.downloadErr
}

func TestDownloadWithRetries(t *testing.T) {
	expectedDownloadPath := "https://artifacts.elastic.co/downloads/beats/elastic-agent"
	testLogger, obs := logger.NewTesting("TestDownloadWithRetries")

	settings := artifact.Config{
		RetryMaxCount:          5,
		RetrySleepInitDuration: 20 * time.Millisecond,
		HTTPTransportSettings: httpcommon.HTTPTransportSettings{
			Timeout: 2 * time.Second,
		},
	}

	// Successful immediately (no retries)
	t.Run("successful_immediately", func(t *testing.T) {
		mockDownloaderCtor := func(version string, log *logger.Logger, settings *artifact.Config) (download.Downloader, error) {
			return &mockDownloader{expectedDownloadPath, nil}, nil
		}

		u := NewUpgrader(testLogger, &settings, &info.AgentInfo{})
		path, err := u.downloadWithRetries(context.Background(), mockDownloaderCtor, "8.9.0", &settings)
		require.NoError(t, err)
		require.Equal(t, expectedDownloadPath, path)

		logs := obs.TakeAll()
		require.Len(t, logs, 1)
		require.Equal(t, fmt.Sprintf("download attempt 1 of %d", settings.RetryMaxCount+1), logs[0].Message)
	})

	// Downloader constructor failing on first attempt, but succeeding on second attempt (= first retry)
	t.Run("constructor_failure_once", func(t *testing.T) {
		attemptIdx := 0
		mockDownloaderCtor := func(version string, log *logger.Logger, settings *artifact.Config) (download.Downloader, error) {
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
		path, err := u.downloadWithRetries(context.Background(), mockDownloaderCtor, "8.9.0", &settings)
		require.NoError(t, err)
		require.Equal(t, expectedDownloadPath, path)

		logs := obs.TakeAll()
		require.Len(t, logs, 3)
		require.Equal(t, fmt.Sprintf("download attempt 1 of %d", settings.RetryMaxCount+1), logs[0].Message)
		require.Contains(t, logs[1].Message, fmt.Sprintf("unable to create fetcher: failed to construct downloader; retrying (will be retry 1 of %d)", settings.RetryMaxCount))
		require.Equal(t, fmt.Sprintf("download attempt 2 of %d", settings.RetryMaxCount+1), logs[2].Message)
	})

	// Download failing on first attempt, but succeeding on second attempt (= first retry)
	t.Run("download_failure_once", func(t *testing.T) {
		attemptIdx := 0
		mockDownloaderCtor := func(version string, log *logger.Logger, settings *artifact.Config) (download.Downloader, error) {
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
		path, err := u.downloadWithRetries(context.Background(), mockDownloaderCtor, "8.9.0", &settings)
		require.NoError(t, err)
		require.Equal(t, expectedDownloadPath, path)

		logs := obs.TakeAll()
		require.Len(t, logs, 3)
		require.Equal(t, fmt.Sprintf("download attempt 1 of %d", settings.RetryMaxCount+1), logs[0].Message)
		require.Contains(t, logs[1].Message, fmt.Sprintf("unable to download package: download failed; retrying (will be retry 1 of %d)", settings.RetryMaxCount))
		require.Equal(t, fmt.Sprintf("download attempt 2 of %d", settings.RetryMaxCount+1), logs[2].Message)
	})

	// Download unsuccessful (all retries exhausted)
	t.Run("download_unsuccessful", func(t *testing.T) {
		mockDownloaderCtor := func(version string, log *logger.Logger, settings *artifact.Config) (download.Downloader, error) {
			return &mockDownloader{"", errors.New("download failed")}, nil
		}

		u := NewUpgrader(testLogger, &settings, &info.AgentInfo{})
		path, err := u.downloadWithRetries(context.Background(), mockDownloaderCtor, "8.9.0", &settings)
		require.Equal(t, "unable to download package: download failed", err.Error())
		require.Equal(t, "", path)

		logs := obs.TakeAll()
		require.Len(t, logs, 11)
		for i := 0; i < int(settings.RetryMaxCount); i++ {
			require.Equal(t, fmt.Sprintf("download attempt %d of %d", i+1, settings.RetryMaxCount+1), logs[(2*i)].Message)
			require.Contains(t, logs[(2*i+1)].Message, fmt.Sprintf("unable to download package: download failed; retrying (will be retry %d of %d)", (i+1), settings.RetryMaxCount))
		}
		require.Equal(t, fmt.Sprintf("download attempt %d of %d", settings.RetryMaxCount+1, settings.RetryMaxCount+1), logs[10].Message)
	})
}
