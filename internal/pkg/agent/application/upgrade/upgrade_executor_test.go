package upgrade

import (
	"context"
	"testing"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact/download"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/details"
	"github.com/elastic/elastic-agent/pkg/core/logger"
	"github.com/elastic/elastic-agent/pkg/core/logger/loggertest"
	agtversion "github.com/elastic/elastic-agent/pkg/version"
	"github.com/stretchr/testify/require"
)

type mockArtifactDownloader struct {
	dowloadArtifactTestFunc                       func(ctx context.Context, parsedVersion *agtversion.ParsedSemVer, sourceURI string, fleetServerURI string, upgradeDetails *details.Details, skipVerifyOverride, skipDefaultPgp bool, pgpBytes ...string) (download.DownloadResult, error)
	cleanNonMatchingVersionsFromDownloadsTestFunc func(log *logger.Logger, version string) error
}

func (m *mockArtifactDownloader) downloadArtifact(ctx context.Context, parsedVersion *agtversion.ParsedSemVer, sourceURI string, fleetServerURI string, upgradeDetails *details.Details, skipVerifyOverride, skipDefaultPgp bool, pgpBytes ...string) (download.DownloadResult, error) {
	return m.dowloadArtifactTestFunc(ctx, parsedVersion, sourceURI, fleetServerURI, upgradeDetails, skipVerifyOverride, skipDefaultPgp, pgpBytes...)
}

func (m *mockArtifactDownloader) cleanNonMatchingVersionsFromDownloads(log *logger.Logger, version string) error {
	return m.cleanNonMatchingVersionsFromDownloadsTestFunc(log, version)
}

type mockUpgradeCleaner struct {
	setupArchiveCleanupTestFunc func(downloadResult download.DownloadResult) error
}

func (m *mockUpgradeCleaner) setupArchiveCleanup(downloadResult download.DownloadResult) error {
	return m.setupArchiveCleanupTestFunc(downloadResult)
}

func (m *mockUpgradeCleaner) setupUnpackCleanup(newHomeDir, oldHomeDir string) error {
	return nil
}

func (m *mockUpgradeCleaner) setupSymlinkCleanup(symlinkFunc changeSymlinkFunc, topDirPath, oldVersionedHome, agentName string) error {
	return nil
}

func (m *mockUpgradeCleaner) cleanup(err error) error {
	return nil
}

func TestDownloadArtifactStep(t *testing.T) {
	ctx := t.Context()
	log, _ := loggertest.New("test")
	parsedVersion, err := agtversion.ParseVersion("9.1.0")
	require.NoError(t, err)

	// agentInfo := &info.AgentInfo{}
	// sourceURI := "mockURI"
	// fleetServerURI := "mockFleetServerURI"
	// upgradeDetails := &details.Details{}

	testValues := struct {
		parsedVersion      *agtversion.ParsedSemVer
		agentInfo          *info.AgentInfo
		sourceURI          string
		fleetServerURI     string
		upgradeDetails     *details.Details
		skipVerifyOverride bool
		skipDefaultPgp     bool
		pgpBytes           []string
	}{
		parsedVersion:      parsedVersion,
		agentInfo:          &info.AgentInfo{},
		sourceURI:          "mockURI",
		fleetServerURI:     "mockFleetServerURI",
		upgradeDetails:     &details.Details{},
		skipVerifyOverride: false,
		skipDefaultPgp:     false,
		pgpBytes:           []string{"mockPGPBytes"},
	}

	mockArtifactDownloader := &mockArtifactDownloader{}
	mockUpgradeCleaner := &mockUpgradeCleaner{}
	upgradeExecutor := &executeUpgrade{
		log:                log,
		artifactDownloader: mockArtifactDownloader,
		upgradeCleaner:     mockUpgradeCleaner,
	}

	nonMatchingCallCount := 0
	mockArtifactDownloader.cleanNonMatchingVersionsFromDownloadsTestFunc = func(log *logger.Logger, version string) error {
		nonMatchingCallCount++
		require.Equal(t, testValues.agentInfo.Version(), version)
		return nil
	}

	mockDownloadResult := download.DownloadResult{
		ArtifactPath:     "mockArtifactPath",
		ArtifactHashPath: "mockArtifactHashPath",
	}
	mockArtifactDownloader.dowloadArtifactTestFunc = func(ctx context.Context, parsedVersion *agtversion.ParsedSemVer, sourceURI string, fleetServerURI string, upgradeDetails *details.Details, skipVerifyOverride, skipDefaultPgp bool, pgpBytes ...string) (download.DownloadResult, error) {
		require.Equal(t, testValues.parsedVersion, parsedVersion)
		require.Equal(t, testValues.sourceURI, sourceURI)
		require.Equal(t, testValues.fleetServerURI, fleetServerURI)
		require.Equal(t, testValues.upgradeDetails, upgradeDetails)
		require.Equal(t, testValues.skipVerifyOverride, skipVerifyOverride)
		require.Equal(t, testValues.skipDefaultPgp, skipDefaultPgp)
		require.Equal(t, testValues.pgpBytes, pgpBytes)
		return mockDownloadResult, nil
	}

	mockUpgradeCleaner.setupArchiveCleanupTestFunc = func(downloadResult download.DownloadResult) error {
		require.Equal(t, mockDownloadResult, downloadResult)
		return nil
	}

	downloadResult, err := upgradeExecutor.downloadArtifact(ctx, testValues.parsedVersion, testValues.agentInfo, testValues.sourceURI, testValues.fleetServerURI, testValues.upgradeDetails, testValues.skipVerifyOverride, testValues.skipDefaultPgp, testValues.pgpBytes...)
	require.NoError(t, err)
	require.Equal(t, mockDownloadResult, downloadResult)
	require.Equal(t, 1, nonMatchingCallCount)
}
