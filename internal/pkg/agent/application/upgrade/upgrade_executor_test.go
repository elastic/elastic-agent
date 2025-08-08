package upgrade

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact/download"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/details"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi"
	"github.com/elastic/elastic-agent/pkg/core/logger"
	"github.com/elastic/elastic-agent/pkg/core/logger/loggertest"
	agtversion "github.com/elastic/elastic-agent/pkg/version"
	"github.com/stretchr/testify/mock"
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

type unpackStepTestCase struct {
	unpackResult            unpackResult
	unpackStepResult        unpackStepResult
	getPackageMetadataError error
	detectFlavorError       error
	unpackError             error
	setupUnpackCleanupError error
	diskSpaceError          error
	checkUpgradeError       error
	unpackStepError         error
	calledUnpackerFuncs     []string
	uncalledUnpackerFuncs   []string
	cleanerCalled           bool
}

func TestUnpackArtifactStep(t *testing.T) {
	currentVersion := agentVersion{
		version: "8.10.0",
	}

	downloadResult := download.DownloadResult{
		ArtifactPath:     "mockArtifactPath",
		ArtifactHashPath: "mockArtifactHashPath",
	}
	version := "9.1.0"
	topPath := "mockTopPath"
	flavor := "mockFlavor"
	dataPath := "mockDataPath"
	currentHome := "mockCurrentHome"
	upgradeDetails := &details.Details{}

	testCases := map[string]unpackStepTestCase{
		"should unpack artifact": {
			unpackResult: unpackResult{
				VersionedHome: "mockVersionedHome",
				Hash:          "mockHash",
			},
			unpackStepResult: unpackStepResult{
				newHome: filepath.Join(topPath, "mockVersionedHome"),
				unpackResult: unpackResult{
					VersionedHome: "mockVersionedHome",
					Hash:          "mockHash",
				},
			},
			getPackageMetadataError: nil,
			detectFlavorError:       nil,
			unpackError:             nil,
			setupUnpackCleanupError: nil,
			checkUpgradeError:       nil,
			diskSpaceError:          nil,
			calledUnpackerFuncs:     []string{"getPackageMetadata", "extractAgentVersion", "detectFlavor", "unpack"},
			uncalledUnpackerFuncs:   []string{},
			unpackStepError:         nil,
			cleanerCalled:           true,
		},
		"when getting package metadata fails, should return error": {
			unpackResult: unpackResult{
				VersionedHome: "mockVersionedHome",
				Hash:          "mockHash",
			},
			unpackStepResult: unpackStepResult{
				newHome: "",
				unpackResult: unpackResult{
					VersionedHome: "",
					Hash:          "",
				},
			},
			getPackageMetadataError: errors.New("test error"),
			detectFlavorError:       nil,
			unpackError:             nil,
			setupUnpackCleanupError: nil,
			checkUpgradeError:       nil,
			diskSpaceError:          nil,
			calledUnpackerFuncs:     []string{"getPackageMetadata"},
			uncalledUnpackerFuncs:   []string{"extractAgentVersion", "detectFlavor", "unpack"},
			unpackStepError:         fmt.Errorf("reading metadata for elastic agent version %s package %q: %w", version, downloadResult.ArtifactPath, errors.New("test error")),
			cleanerCalled:           false,
		},
		"when checking upgrade fails, should return error": {
			unpackResult: unpackResult{
				VersionedHome: "mockVersionedHome",
				Hash:          "mockHash",
			},
			unpackStepResult: unpackStepResult{
				newHome: "",
				unpackResult: unpackResult{
					VersionedHome: "",
					Hash:          "",
				},
			},
			getPackageMetadataError: nil,
			detectFlavorError:       nil,
			unpackError:             nil,
			setupUnpackCleanupError: nil,
			checkUpgradeError:       errors.New("test error"),
			diskSpaceError:          nil,
			calledUnpackerFuncs:     []string{"getPackageMetadata", "extractAgentVersion"},
			uncalledUnpackerFuncs:   []string{"detectFlavor", "unpack"},
			unpackStepError:         fmt.Errorf("cannot upgrade the agent: %w", errors.New("test error")),
			cleanerCalled:           false,
		},
		"when detecting flavor fails, should unpack artifact with default flavor": {
			unpackResult: unpackResult{
				VersionedHome: "mockVersionedHome",
				Hash:          "mockHash",
			},
			unpackStepResult: unpackStepResult{
				newHome: filepath.Join(topPath, "mockVersionedHome"),
				unpackResult: unpackResult{
					VersionedHome: "mockVersionedHome",
					Hash:          "mockHash",
				},
			},
			getPackageMetadataError: nil,
			detectFlavorError:       errors.New("test error"),
			unpackError:             nil,
			setupUnpackCleanupError: nil,
			checkUpgradeError:       nil,
			diskSpaceError:          nil,
			calledUnpackerFuncs:     []string{"getPackageMetadata", "extractAgentVersion", "detectFlavor", "unpack"},
			uncalledUnpackerFuncs:   []string{},
			unpackStepError:         nil,
			cleanerCalled:           true,
		},
		"when unpacking fails, should return error": {
			unpackResult: unpackResult{
				VersionedHome: "mockVersionedHome",
				Hash:          "mockHash",
			},
			unpackStepResult: unpackStepResult{
				newHome: filepath.Join(topPath, "mockVersionedHome"),
				unpackResult: unpackResult{
					VersionedHome: "mockVersionedHome",
					Hash:          "mockHash",
				},
			},
			getPackageMetadataError: nil,
			detectFlavorError:       nil,
			unpackError:             errors.New("test error"),
			setupUnpackCleanupError: nil,
			checkUpgradeError:       nil,
			diskSpaceError:          errors.New("test error"),
			calledUnpackerFuncs:     []string{"getPackageMetadata", "extractAgentVersion", "detectFlavor", "unpack"},
			uncalledUnpackerFuncs:   []string{},
			unpackStepError:         errors.New("test error"),
			cleanerCalled:           true,
		},
		"if versioned home is unknown, should return error": {
			unpackResult: unpackResult{
				VersionedHome: "",
				Hash:          "mockHash",
			},
			unpackStepResult: unpackStepResult{
				newHome: "",
				unpackResult: unpackResult{
					VersionedHome: "",
					Hash:          "",
				},
			},
			getPackageMetadataError: nil,
			detectFlavorError:       nil,
			unpackError:             nil,
			setupUnpackCleanupError: nil,
			checkUpgradeError:       nil,
			diskSpaceError:          nil,
			calledUnpackerFuncs:     []string{"getPackageMetadata", "extractAgentVersion", "detectFlavor", "unpack"},
			uncalledUnpackerFuncs:   []string{},
			unpackStepError:         errors.New("unknown versioned home"),
			cleanerCalled:           false,
		},
		"if hash is unknown, should return error": {
			unpackResult: unpackResult{
				VersionedHome: "mockVersionedHome",
				Hash:          "",
			},
			unpackStepResult: unpackStepResult{
				newHome: "",
				unpackResult: unpackResult{
					VersionedHome: "",
					Hash:          "",
				},
			},
			getPackageMetadataError: nil,
			detectFlavorError:       nil,
			unpackError:             nil,
			setupUnpackCleanupError: nil,
			checkUpgradeError:       nil,
			diskSpaceError:          nil,
			calledUnpackerFuncs:     []string{"getPackageMetadata", "extractAgentVersion", "detectFlavor", "unpack"},
			uncalledUnpackerFuncs:   []string{},
			unpackStepError:         errors.New("unknown hash"),
			cleanerCalled:           false,
		},
		"if setup unpack cleanup fails, should return error": {
			unpackResult: unpackResult{
				VersionedHome: "mockVersionedHome",
				Hash:          "mockHash",
			},
			unpackStepResult: unpackStepResult{
				newHome: filepath.Join(topPath, "mockVersionedHome"),
				unpackResult: unpackResult{
					VersionedHome: "mockVersionedHome",
					Hash:          "mockHash",
				},
			},
			getPackageMetadataError: nil,
			detectFlavorError:       nil,
			unpackError:             nil,
			setupUnpackCleanupError: errors.New("test error"),
			checkUpgradeError:       nil,
			diskSpaceError:          nil,
			calledUnpackerFuncs:     []string{"getPackageMetadata", "extractAgentVersion", "detectFlavor", "unpack"},
			uncalledUnpackerFuncs:   []string{},
			unpackStepError:         errors.New("test error"),
			cleanerCalled:           true,
		},
		"if unpack fails, and versioned home is unknown, should return combined error": {
			unpackResult: unpackResult{
				VersionedHome: "",
				Hash:          "mockHash",
			},
			unpackStepResult: unpackStepResult{
				newHome: "",
				unpackResult: unpackResult{
					VersionedHome: "",
					Hash:          "",
				},
			},
			getPackageMetadataError: nil,
			detectFlavorError:       nil,
			unpackError:             errors.New("test error"),
			setupUnpackCleanupError: nil,
			checkUpgradeError:       nil,
			diskSpaceError:          errors.New("test error"),
			calledUnpackerFuncs:     []string{"getPackageMetadata", "extractAgentVersion", "detectFlavor", "unpack"},
			uncalledUnpackerFuncs:   []string{},
			unpackStepError:         errors.Join(errors.New("test error"), errors.New("unknown versioned home")),
			cleanerCalled:           false,
		},
		"if unpack fails, and hash is unknown, should return combined error": {
			unpackResult: unpackResult{
				VersionedHome: "mockVersionedHome",
				Hash:          "",
			},
			unpackStepResult: unpackStepResult{
				newHome: "",
				unpackResult: unpackResult{
					VersionedHome: "",
					Hash:          "",
				},
			},
			getPackageMetadataError: nil,
			detectFlavorError:       nil,
			unpackError:             errors.New("test error"),
			setupUnpackCleanupError: nil,
			checkUpgradeError:       nil,
			diskSpaceError:          errors.New("test error"),
			calledUnpackerFuncs:     []string{"getPackageMetadata", "extractAgentVersion", "detectFlavor", "unpack"},
			uncalledUnpackerFuncs:   []string{},
			unpackStepError:         errors.Join(errors.New("test error"), errors.New("unknown hash")),
			cleanerCalled:           false,
		},
		"if unpack fails, and setup unpack cleanup fails, should return combined error": {
			unpackResult: unpackResult{
				VersionedHome: "mockVersionedHome",
				Hash:          "mockHash",
			},
			unpackStepResult: unpackStepResult{
				newHome: filepath.Join(topPath, "mockVersionedHome"),
				unpackResult: unpackResult{
					VersionedHome: "mockVersionedHome",
					Hash:          "mockHash",
				},
			},
			getPackageMetadataError: nil,
			detectFlavorError:       nil,
			unpackError:             errors.New("test unpack error"),
			setupUnpackCleanupError: errors.New("test setup unpack cleanup error"),
			checkUpgradeError:       nil,
			diskSpaceError:          errors.New("test unpack error"),
			calledUnpackerFuncs:     []string{"getPackageMetadata", "extractAgentVersion", "detectFlavor", "unpack"},
			uncalledUnpackerFuncs:   []string{},
			unpackStepError:         errors.Join(errors.New("test unpack error"), errors.New("test setup unpack cleanup error")),
			cleanerCalled:           true,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			log, _ := loggertest.New("test")

			mockUnpacker := &mock_unpacker{}
			mockUpgradeCleaner := &mock_upgradeCleaner{}

			mockMetadata := packageMetadata{}
			newVersion := agentVersion{}
			detectedFlavor := "mockDetectedFlavor"

			newHome := filepath.Join(topPath, tc.unpackResult.VersionedHome)

			checkUpgradeFn := func(log *logger.Logger, currentVersion, newVersion agentVersion, metadata packageMetadata) error {
				return tc.checkUpgradeError
			}

			for _, calledFunc := range tc.calledUnpackerFuncs {
				switch calledFunc {
				case "getPackageMetadata":
					mockUnpacker.EXPECT().getPackageMetadata(downloadResult.ArtifactPath).Return(mockMetadata, tc.getPackageMetadataError)
				case "extractAgentVersion":
					mockUnpacker.EXPECT().extractAgentVersion(mockMetadata, version).Return(newVersion)
				case "detectFlavor":
					mockUnpacker.EXPECT().detectFlavor(topPath, "").Return(detectedFlavor, tc.detectFlavorError)
				case "unpack":
					mockUnpacker.EXPECT().unpack(version, downloadResult.ArtifactPath, dataPath, detectedFlavor).Return(tc.unpackResult, tc.unpackError)
				}
			}

			if tc.cleanerCalled {
				mockUpgradeCleaner.EXPECT().setupUnpackCleanup(newHome, currentHome).Return(tc.setupUnpackCleanupError)
			}

			var diskSpaceErrorCalledWith error
			upgradeExecutor := &executeUpgrade{
				log:            log,
				unpacker:       mockUnpacker,
				upgradeCleaner: mockUpgradeCleaner,
				diskSpaceErrorFunc: func(err error) error {
					diskSpaceErrorCalledWith = err
					return err
				},
			}

			unpackStepRes, err := upgradeExecutor.unpackArtifact(downloadResult, version, downloadResult.ArtifactPath, topPath, flavor, dataPath, currentHome, upgradeDetails, currentVersion, checkUpgradeFn)

			mockUnpacker.AssertExpectations(t)

			if tc.cleanerCalled {
				mockUpgradeCleaner.AssertExpectations(t)
			} else {
				mockUpgradeCleaner.AssertNotCalled(t, "setupUnpackCleanup", "expected %v to not be called", tc.cleanerCalled)
			}

			for _, uncalledFunc := range tc.uncalledUnpackerFuncs {
				mockUnpacker.AssertNotCalled(t, uncalledFunc, "expected %v to not be called", uncalledFunc)
			}

			require.Equal(t, details.StateExtracting, upgradeDetails.State, "expected state to be %v, got %v", details.StateExtracting, upgradeDetails.State)

			if tc.unpackStepError != nil {
				require.Equal(t, tc.unpackStepError.Error(), err.Error(), "expected unpack step error to be %v, got %v", tc.unpackStepError, err)
			} else {
				require.NoError(t, err)
			}

			require.Equal(t, tc.unpackStepResult, unpackStepRes, "expected unpack step result to be %v, got %v", tc.unpackStepResult, unpackStepRes)

			require.Equal(t, tc.diskSpaceError, diskSpaceErrorCalledWith, "expected disk space error to be %v, got %v", tc.diskSpaceError, diskSpaceErrorCalledWith)
		})
	}
}

type replaceOldWithNewTestCase struct {
	copyActionStoreError         error
	copyRunDirectoryError        error
	setupSymlinkCleanupError     error
	setupSymlinkCleanupCalled    bool
	changeSymlinkError           error
	changeSymlinkCalled          bool
	upgradeDetailsStateSet       bool
	calledDirectoryCopierFuncs   []string
	uncalledDirectoryCopierFuncs []string
	diskSpaceErrorFuncCalled     bool
	diskSpaceError               error
	expectedError                error
}

func TestReplaceOldWithNewStep(t *testing.T) {
	log, _ := loggertest.New("test")

	unpackStepResult := unpackStepResult{
		newHome: "mockNewHome",
		unpackResult: unpackResult{
			VersionedHome: "mockVersionedHome",
			Hash:          "mockHash",
		},
	}
	currentVersionedHome := "mockCurrentVersionedHome"
	topPath := "mockTopPath"
	agentName := "mockAgentName"
	currentHome := "mockCurrentHome"
	oldRunPath := "mockOldRunPath"
	newRunPath := "mockNewRunPath"
	symlinkPath := "mockSymlinkPath"
	newBinPath := "mockNewBinPath"

	testCases := map[string]replaceOldWithNewTestCase{
		"should migrate action store and run directory and change symlink": {
			copyActionStoreError:         nil,
			copyRunDirectoryError:        nil,
			setupSymlinkCleanupError:     nil,
			setupSymlinkCleanupCalled:    true,
			changeSymlinkError:           nil,
			changeSymlinkCalled:          true,
			upgradeDetailsStateSet:       true,
			calledDirectoryCopierFuncs:   []string{"copyActionStore", "copyRunDirectory"},
			uncalledDirectoryCopierFuncs: []string{},
			diskSpaceErrorFuncCalled:     false,
			diskSpaceError:               nil,
			expectedError:                nil,
		},
		"if copying action store fails, should return error": {
			copyActionStoreError:         errors.New("test error"),
			copyRunDirectoryError:        nil,
			setupSymlinkCleanupError:     nil,
			setupSymlinkCleanupCalled:    false,
			changeSymlinkError:           nil,
			changeSymlinkCalled:          false,
			upgradeDetailsStateSet:       false,
			calledDirectoryCopierFuncs:   []string{"copyActionStore"},
			uncalledDirectoryCopierFuncs: []string{"copyRunDirectory"},
			diskSpaceErrorFuncCalled:     true,
			diskSpaceError:               errors.New("test error"),
			expectedError:                fmt.Errorf("failed to copy action store: %w", errors.New("test error")),
		},
		"if copying run directory fails, should return error": {
			copyActionStoreError:         nil,
			copyRunDirectoryError:        errors.New("test error"),
			setupSymlinkCleanupError:     nil,
			setupSymlinkCleanupCalled:    false,
			changeSymlinkError:           nil,
			changeSymlinkCalled:          false,
			upgradeDetailsStateSet:       false,
			calledDirectoryCopierFuncs:   []string{"copyActionStore", "copyRunDirectory"},
			uncalledDirectoryCopierFuncs: []string{},
			diskSpaceErrorFuncCalled:     true,
			diskSpaceError:               errors.New("test error"),
			expectedError:                fmt.Errorf("failed to copy run directory: %w", errors.New("test error")),
		},
		"if setting up symlink cleanup fails, should return error": {
			copyActionStoreError:         nil,
			copyRunDirectoryError:        nil,
			setupSymlinkCleanupError:     errors.New("test error"),
			setupSymlinkCleanupCalled:    true,
			changeSymlinkError:           nil,
			changeSymlinkCalled:          false,
			upgradeDetailsStateSet:       true,
			calledDirectoryCopierFuncs:   []string{"copyActionStore", "copyRunDirectory"},
			uncalledDirectoryCopierFuncs: []string{},
			diskSpaceErrorFuncCalled:     false,
			diskSpaceError:               nil,
			expectedError:                fmt.Errorf("error setting up symlink cleanup: %w", errors.New("test error")),
		},
		"if changing symlink fails, should return error": {
			copyActionStoreError:         nil,
			copyRunDirectoryError:        nil,
			setupSymlinkCleanupError:     nil,
			setupSymlinkCleanupCalled:    true,
			changeSymlinkError:           errors.New("test error"),
			changeSymlinkCalled:          true,
			upgradeDetailsStateSet:       true,
			calledDirectoryCopierFuncs:   []string{"copyActionStore", "copyRunDirectory"},
			uncalledDirectoryCopierFuncs: []string{},
			diskSpaceErrorFuncCalled:     false,
			diskSpaceError:               nil,
			expectedError:                errors.New("test error"),
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			upgradeDetails := &details.Details{}

			mockDirectoryCopier := &mock_agentDirectoryCopier{}
			mockUpgradeCleaner := &mock_upgradeCleaner{}
			mockRelinker := &mock_relinker{}

			for _, calledFunc := range tc.calledDirectoryCopierFuncs {
				switch calledFunc {
				case "copyActionStore":
					mockDirectoryCopier.EXPECT().copyActionStore(log, unpackStepResult.newHome).Return(tc.copyActionStoreError)
				case "copyRunDirectory":
					mockDirectoryCopier.EXPECT().copyRunDirectory(log, oldRunPath, newRunPath).Return(tc.copyRunDirectoryError)
				}
			}

			if tc.setupSymlinkCleanupCalled {
				mockUpgradeCleaner.EXPECT().setupSymlinkCleanup(mock.AnythingOfType("upgrade.changeSymlinkFunc"), topPath, currentVersionedHome, agentName).Return(tc.setupSymlinkCleanupError)
			}

			if tc.changeSymlinkCalled {
				mockRelinker.EXPECT().changeSymlink(log, topPath, symlinkPath, newBinPath).Return(tc.changeSymlinkError)
			}

			var diskSpaceErrorCalledWith error
			diskSpaceErrorFuncCalled := false
			upgradeExecutor := &executeUpgrade{
				log:             log,
				upgradeCleaner:  mockUpgradeCleaner,
				directoryCopier: mockDirectoryCopier,
				relinker:        mockRelinker,
				diskSpaceErrorFunc: func(err error) error {
					diskSpaceErrorFuncCalled = true
					diskSpaceErrorCalledWith = err
					return err
				},
			}

			err := upgradeExecutor.replaceOldWithNew(unpackStepResult, currentVersionedHome, topPath, agentName, currentHome, oldRunPath, newRunPath, symlinkPath, newBinPath, upgradeDetails)

			mockDirectoryCopier.AssertExpectations(t)

			if tc.setupSymlinkCleanupCalled {
				mockUpgradeCleaner.AssertExpectations(t)
			} else {
				mockUpgradeCleaner.AssertNotCalled(t, "setupSymlinkCleanup", "expected setupSymlinkCleanup to not be called")
			}

			if tc.changeSymlinkCalled {
				mockRelinker.AssertExpectations(t)
			} else {
				mockRelinker.AssertNotCalled(t, "changeSymlink", "expected changeSymlink to not be called")
			}

			if tc.upgradeDetailsStateSet {
				require.Equal(t, details.StateReplacing, upgradeDetails.State, "expected state to be %v, got %v", details.StateReplacing, upgradeDetails.State)
			} else {
				require.Empty(t, upgradeDetails.State, "expected state to be empty, got %v", upgradeDetails.State)
			}

			require.Equal(t, tc.diskSpaceError, diskSpaceErrorCalledWith, "expected disk space error to be %v, got %v", tc.diskSpaceError, diskSpaceErrorCalledWith)
			require.Equal(t, tc.diskSpaceErrorFuncCalled, diskSpaceErrorFuncCalled, "expected disk space error func to be called")

			if tc.expectedError != nil {
				require.Equal(t, tc.expectedError.Error(), err.Error(), "expected error to be %s, got %v", tc.expectedError, err)
				return
			}

			require.NoError(t, err, "expected no error, got %v", err)
		})
	}
}

type watchNewAgentTestCase struct {
	markUpgradeError    error
	invokeWatcherError  error
	waitForWatcherError error
	calledFuncs         []string
	uncalledFuncs       []string
	expectedError       error
}

func TestWatchNewAgentStep(t *testing.T) {
	log, _ := loggertest.New("test")
	ctx := t.Context()

	markerFilePath := "mockMarkerFilePath"
	topPath := "mockTopPath"
	dataPath := "mockDataPath"
	watcherExecutable := "mockWatcherExecutable"
	waitTime := time.Second * 10

	var createTimeoutContext createContextWithTimeout

	newAgentInstall := agentInstall{
		versionedHome: "mockNewVersionedHome",
		hash:          "mockNewHash",
	}
	previousAgentInstall := agentInstall{
		versionedHome: "mockPreviousVersionedHome",
		hash:          "mockPreviousHash",
	}
	action := &fleetapi.ActionUpgrade{}
	upgradeDetails := &details.Details{}
	upgradeOutcome := OUTCOME_UPGRADE
	watcherCmd := &exec.Cmd{}
	watcherCmd.Process = &os.Process{}

	testCases := map[string]watchNewAgentTestCase{
		"should mark upgrade and invoke watcher": {
			markUpgradeError:    nil,
			invokeWatcherError:  nil,
			waitForWatcherError: nil,
			calledFuncs:         []string{"markUpgrade", "selectWatcherExecutable", "invokeWatcher", "waitForWatcher"},
			uncalledFuncs:       []string{},
			expectedError:       nil,
		},
		"should return error if marking upgrade fails": {
			markUpgradeError:    errors.New("test error"),
			invokeWatcherError:  nil,
			waitForWatcherError: nil,
			calledFuncs:         []string{"markUpgrade"},
			uncalledFuncs:       []string{"selectWatcherExecutable", "invokeWatcher", "waitForWatcher"},
			expectedError:       errors.New("test error"),
		},
		"should return error if invoking watcher fails": {
			markUpgradeError:    nil,
			invokeWatcherError:  errors.New("test error"),
			waitForWatcherError: nil,
			calledFuncs:         []string{"markUpgrade", "selectWatcherExecutable", "invokeWatcher"},
			uncalledFuncs:       []string{"waitForWatcher"},
			expectedError:       errors.New("test error"),
		},
		"if waiting for watcher fails, should kill watcher process and return combined error": {
			markUpgradeError:    nil,
			invokeWatcherError:  nil,
			waitForWatcherError: errors.New("test error"),
			calledFuncs:         []string{"markUpgrade", "selectWatcherExecutable", "invokeWatcher", "waitForWatcher"},
			uncalledFuncs:       []string{},
			expectedError:       errors.Join(errors.New("test error"), errors.New("os: process not initialized")),
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			mockWatcher := &mock_watcher{}

			upgradeExecutor := &executeUpgrade{
				log:     log,
				watcher: mockWatcher,
			}

			for _, calledFunc := range tc.calledFuncs {
				switch calledFunc {
				case "markUpgrade":
					mockWatcher.EXPECT().markUpgrade(log, dataPath, newAgentInstall, previousAgentInstall, action, upgradeDetails, upgradeOutcome).Return(tc.markUpgradeError)
				case "selectWatcherExecutable":
					mockWatcher.EXPECT().selectWatcherExecutable(topPath, previousAgentInstall, newAgentInstall).Return(watcherExecutable)
				case "invokeWatcher":
					mockWatcher.EXPECT().invokeWatcher(log, watcherExecutable).Return(watcherCmd, tc.invokeWatcherError)
				case "waitForWatcher":
					mockWatcher.EXPECT().waitForWatcher(ctx, log, markerFilePath, waitTime, mock.AnythingOfType("upgrade.createContextWithTimeout")).Return(tc.waitForWatcherError)
				}
			}

			err := upgradeExecutor.watchNewAgent(ctx, markerFilePath, topPath, dataPath, waitTime, createTimeoutContext, newAgentInstall, previousAgentInstall, action, upgradeDetails, upgradeOutcome)

			mockWatcher.AssertExpectations(t)
			for _, uncalledFunc := range tc.uncalledFuncs {
				mockWatcher.AssertNotCalled(t, uncalledFunc, "expected %v to not be called", uncalledFunc)
			}

			if tc.expectedError != nil {
				require.Equal(t, tc.expectedError.Error(), err.Error(), "expected error to be %v, got %v", tc.expectedError, err)
				return
			}

			require.NoError(t, err)

		})
	}
}
