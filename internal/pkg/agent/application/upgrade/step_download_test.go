package upgrade

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"

	"github.com/elastic/elastic-agent-libs/transport/httpcommon"

	"github.com/elastic/elastic-agent/pkg/core/logger"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact/download"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact"
)

type mockDownloader struct {
	downloadErr  error
	downloadPath string
}

func (md *mockDownloader) Download(ctx context.Context, agentArtifact artifact.Artifact, version string) (string, error) {
	return md.downloadPath, md.downloadErr
}

func TestDownloadWithRetries(t *testing.T) {
	testLogger, obs := logger.NewTesting("TestDownloadWithRetries")

	// Successful immediately (no retries)
	t.Run("successful_immediately", func(t *testing.T) {
		expectedDownloadPath := "https://artifacts.elastic.co/downloads/beats/elastic-agent"
		mockDownloaderCtor := func(version string, log *logger.Logger, settings *artifact.Config) (download.Downloader, error) {
			return &mockDownloader{
				downloadErr:  nil,
				downloadPath: expectedDownloadPath,
			}, nil
		}

		settings := artifact.Config{
			RetryMaxCount: 10,
			HTTPTransportSettings: httpcommon.HTTPTransportSettings{
				Timeout: 2 * time.Second,
			},
		}

		u := NewUpgrader(testLogger, &settings, &info.AgentInfo{})
		path, err := u.downloadWithRetries(context.Background(), mockDownloaderCtor, "8.9.0", &settings)
		require.NoError(t, err)
		require.Equal(t, expectedDownloadPath, path)

		logs := obs.All()
		require.Len(t, logs, 1)
		require.Equal(t, "download attempt 1 of 11", logs[0].Message)
	})

	// Successful after first attempt (at least one retry) with
	// downloader constructor failing

	// Successful after first attempt (at least one retry) with
	// download failing

	// Unsuccessful (all retries exhausted)
}
