package upgrade

import (
	"testing"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact/download"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/details"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/pkg/core/logger/loggertest"
	agtversion "github.com/elastic/elastic-agent/pkg/version"
	"github.com/stretchr/testify/require"
)

type downloadStepTestCase struct {
	cleanNonMatchingVersionsFromDownloadsErrors []error
	expectedLogMessage                          string
	downloadArtifactError                       error
	setupArchiveCleanupError                    error
	setupArchiveCleanupCalled                   bool
}

func TestDownloadArtifactStep(t *testing.T) {
	ctx := t.Context()
	parsedVersion, err := agtversion.ParseVersion("9.1.0")
	require.NoError(t, err)

	agentInfo := &info.AgentInfo{}
	sourceURI := "mockURI"
	fleetServerURI := "mockFleetServerURI"
	upgradeDetails := &details.Details{}
	skipVerifyOverride := false
	skipDefaultPgp := false
	pgpBytes := []string{"mockPGPBytes"}

	testCases := map[string]downloadStepTestCase{
		"should download artifact and setup archive cleanup": {
			cleanNonMatchingVersionsFromDownloadsErrors: []error{nil},
			expectedLogMessage:                          "",
			downloadArtifactError:                       nil,
			setupArchiveCleanupError:                    nil,
			setupArchiveCleanupCalled:                   true,
		},
		"when initial cleanup of non-matching versions fails, should log error": {
			cleanNonMatchingVersionsFromDownloadsErrors: []error{errors.New("test error")},
			expectedLogMessage:                          "Unable to clean downloads before update",
			downloadArtifactError:                       nil,
			setupArchiveCleanupError:                    nil,
			setupArchiveCleanupCalled:                   true,
		},
		"when download fails, and cleanup of non-matching versions succeeds, should return error": {
			cleanNonMatchingVersionsFromDownloadsErrors: []error{nil, nil},
			expectedLogMessage:                          "",
			downloadArtifactError:                       errors.New("test error"),
			setupArchiveCleanupError:                    nil,
			setupArchiveCleanupCalled:                   false,
		},
		"when download fails, and cleanup of non-matching versions fails, should log error and return error": {
			cleanNonMatchingVersionsFromDownloadsErrors: []error{nil, errors.New("test non-matching error")},
			expectedLogMessage:                          "Unable to remove file after verification failure",
			downloadArtifactError:                       errors.New("test download error"),
			setupArchiveCleanupError:                    nil,
			setupArchiveCleanupCalled:                   false,
		},
		"when download succeeds, but setting up archive cleanup fails, should return error": {
			cleanNonMatchingVersionsFromDownloadsErrors: []error{nil},
			expectedLogMessage:                          "",
			downloadArtifactError:                       nil,
			setupArchiveCleanupError:                    errors.New("test cleanup error"),
			setupArchiveCleanupCalled:                   true,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			log, obs := loggertest.New("test")

			mockArtifactDownloader := &mock_artifactDownloader{}
			mockUpgradeCleaner := &mock_upgradeCleaner{}

			upgradeExecutor := &executeUpgrade{
				log:                log,
				artifactDownloader: mockArtifactDownloader,
				upgradeCleaner:     mockUpgradeCleaner,
			}

			mockDownloadResult := download.DownloadResult{
				ArtifactPath:     "mockArtifactPath",
				ArtifactHashPath: "mockArtifactHashPath",
			}

			pgpBytesConverted := make([]interface{}, len(pgpBytes))
			for i, v := range pgpBytes {
				pgpBytesConverted[i] = v
			}

			for _, err := range tc.cleanNonMatchingVersionsFromDownloadsErrors {
				mockArtifactDownloader.EXPECT().cleanNonMatchingVersionsFromDownloads(log, agentInfo.Version()).Return(err).Once()
			}
			mockArtifactDownloader.EXPECT().downloadArtifact(
				ctx,
				parsedVersion,
				sourceURI,
				fleetServerURI,
				upgradeDetails,
				skipVerifyOverride,
				skipDefaultPgp,
				pgpBytesConverted...,
			).Return(mockDownloadResult, tc.downloadArtifactError)

			if tc.setupArchiveCleanupCalled {
				mockUpgradeCleaner.EXPECT().setupArchiveCleanup(mockDownloadResult).Return(tc.setupArchiveCleanupError)
			}

			downloadResult, err := upgradeExecutor.downloadArtifact(ctx, parsedVersion, agentInfo, sourceURI, fleetServerURI, upgradeDetails, skipVerifyOverride, skipDefaultPgp, pgpBytes...)

			mockArtifactDownloader.AssertExpectations(t)
			mockUpgradeCleaner.AssertExpectations(t)

			require.Equal(t, details.StateDownloading, upgradeDetails.State)

			if !tc.setupArchiveCleanupCalled {
				mockUpgradeCleaner.AssertNotCalled(t, "setupArchiveCleanup")
			}

			if tc.expectedLogMessage != "" {
				require.Equal(t, tc.expectedLogMessage, obs.All()[0].Message)
			}

			if tc.downloadArtifactError != nil || tc.setupArchiveCleanupError != nil {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}

			require.Equal(t, mockDownloadResult, downloadResult)
		})
	}
}
