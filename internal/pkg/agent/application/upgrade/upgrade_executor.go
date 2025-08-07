package upgrade

import (
	"context"
	goerrors "errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact/download"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/details"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi"
	"github.com/elastic/elastic-agent/pkg/core/logger"
	agtversion "github.com/elastic/elastic-agent/pkg/version"
)

type artifactDownloader interface {
	downloadArtifact(ctx context.Context, parsedVersion *agtversion.ParsedSemVer, sourceURI string, fleetServerURI string, upgradeDetails *details.Details, skipVerifyOverride, skipDefaultPgp bool, pgpBytes ...string) (download.DownloadResult, error)
	cleanNonMatchingVersionsFromDownloads(log *logger.Logger, version string) error
}

type unpacker interface {
	getPackageMetadata(archivePath string) (packageMetadata, error)
	extractAgentVersion(metadata packageMetadata, version string) agentVersion
	unpack(version, archivePath, topPath, flavor string) (unpackResult, error)
	detectFlavor(topPath, flavor string) (string, error)
}

type relinker interface {
	changeSymlink(log *logger.Logger, topDirPath, symlinkPath, newTarget string) error
}

type createContextWithTimeout func(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc)

type watcher interface {
	waitForWatcher(ctx context.Context, log *logger.Logger, markerFilePath string, waitTime time.Duration, createTimeoutContext createContextWithTimeout) error
	selectWatcherExecutable(topDir string, previous agentInstall, current agentInstall) string
	markUpgrade(log *logger.Logger, dataDir string, current, previous agentInstall, action *fleetapi.ActionUpgrade, det *details.Details, outcome UpgradeOutcome) error
	invokeWatcher(log *logger.Logger, agentExecutable string) (*exec.Cmd, error)
}

type agentDirectoryCopier interface {
	copyActionStore(log *logger.Logger, newHome string) error
	copyRunDirectory(log *logger.Logger, oldRunPath, newRunPath string) error
}

type executeUpgrade struct {
	log                *logger.Logger
	upgradeCleaner     upgradeCleaner
	artifactDownloader artifactDownloader
	unpacker           unpacker
	relinker           relinker
	watcher            watcher
	directoryCopier    agentDirectoryCopier
	diskSpaceErrorFunc func(error) error
}

type unpackStepResult struct {
	newHome string
	unpackResult
}

func (u *executeUpgrade) downloadArtifact(ctx context.Context, parsedTargetVersion *agtversion.ParsedSemVer, agentInfo info.Agent, sourceURI string, fleetServerURI string, upgradeDetails *details.Details, skipVerifyOverride, skipDefaultPgp bool, pgpBytes ...string) (download.DownloadResult, error) {
	err := u.artifactDownloader.cleanNonMatchingVersionsFromDownloads(u.log, agentInfo.Version())
	if err != nil {
		u.log.Errorw("Unable to clean downloads before update", "error.message", err, "downloads.path", paths.Downloads())
	}

	upgradeDetails.SetState(details.StateDownloading)

	downloadResult, err := u.artifactDownloader.downloadArtifact(ctx, parsedTargetVersion, sourceURI, fleetServerURI, upgradeDetails, skipVerifyOverride, skipDefaultPgp, pgpBytes...)
	if err != nil {
		// Run the same pre-upgrade cleanup task to get rid of any newly downloaded files
		// This may have an issue if users are upgrading to the same version number.
		if dErr := u.artifactDownloader.cleanNonMatchingVersionsFromDownloads(u.log, agentInfo.Version()); dErr != nil {
			u.log.Errorw("Unable to remove file after verification failure", "error.message", dErr)
		}

		return downloadResult, err
	}

	return downloadResult, u.upgradeCleaner.setupArchiveCleanup(downloadResult)
}

func (u *executeUpgrade) unpackArtifact(downloadResult download.DownloadResult, version, archivePath, topPath, flavor, dataPath, currentHome string, upgradeDetails *details.Details, currentVersion agentVersion) (unpackStepResult, error) {
	upgradeDetails.SetState(details.StateExtracting)

	metadata, err := u.unpacker.getPackageMetadata(downloadResult.ArtifactPath)
	if err != nil {
		return unpackStepResult{}, fmt.Errorf("reading metadata for elastic agent version %s package %q: %w", version, downloadResult.ArtifactPath, err)
	}

	newVersion := u.unpacker.extractAgentVersion(metadata, version)

	if err := checkUpgrade(u.log, currentVersion, newVersion, metadata); err != nil {
		return unpackStepResult{}, fmt.Errorf("cannot upgrade the agent: %w", err)
	}

	u.log.Infow("Unpacking agent package", "version", newVersion)

	// Nice to have: add check that no archive files end up in the current versioned home
	// default to no flavor to avoid breaking behavior

	// no default flavor, keep everything in case flavor is not specified
	// in case of error fallback to keep-all
	detectedFlavor, detectFlavorErr := u.unpacker.detectFlavor(topPath, "")
	if detectFlavorErr != nil {
		u.log.Warnf("error encountered when detecting used flavor with top path %q: %w", topPath, detectFlavorErr)
	}
	u.log.Debugf("detected used flavor: %q", detectedFlavor)

	unpackRes, unpackErr := u.unpacker.unpack(version, downloadResult.ArtifactPath, dataPath, detectedFlavor)
	unpackErr = u.diskSpaceErrorFunc(unpackErr)

	if unpackRes.VersionedHome == "" {
		return unpackStepResult{}, goerrors.Join(unpackErr, errors.New("unknown versioned home"))
	}

	newHash := unpackRes.Hash
	if newHash == "" {
		return unpackStepResult{}, goerrors.Join(unpackErr, errors.New("unknown hash"))
	}

	newHome := filepath.Join(topPath, unpackRes.VersionedHome)

	unpackStepResult := unpackStepResult{
		newHome:      newHome,
		unpackResult: unpackRes,
	}

	if err := u.upgradeCleaner.setupUnpackCleanup(newHome, currentHome); err != nil {
		return unpackStepResult, goerrors.Join(unpackErr, err)
	}

	return unpackStepResult, unpackErr
}

func (u *executeUpgrade) replaceOldWithNew(log *logger.Logger, unpackStepResult unpackStepResult, currentVersionedHome, topPath, agentName, currentHome, oldRunPath, newRunPath, symlinkPath, newBinPath string, upgradeDetails *details.Details) error {
	if err := u.directoryCopier.copyActionStore(u.log, unpackStepResult.newHome); err != nil {
		return fmt.Errorf("failed to copy action store: %w", u.diskSpaceErrorFunc(err))
	}

	if err := u.directoryCopier.copyRunDirectory(u.log, oldRunPath, newRunPath); err != nil {
		return fmt.Errorf("failed to copy run directory: %w", u.diskSpaceErrorFunc(err))
	}

	upgradeDetails.SetState(details.StateReplacing)

	if err := u.upgradeCleaner.setupSymlinkCleanup(u.relinker.changeSymlink, topPath, currentVersionedHome, agentName); err != nil {
		return fmt.Errorf("error setting up symlink cleanup: %w", err)
	}

	return u.relinker.changeSymlink(u.log, topPath, symlinkPath, newBinPath)
}

func (u *executeUpgrade) watchNewAgent(ctx context.Context, log *logger.Logger, markerFilePath, topPath, dataPath string, waitTime time.Duration, createTimeoutContext createContextWithTimeout, newAgentInstall agentInstall, previousAgentInstall agentInstall, action *fleetapi.ActionUpgrade, upgradeDetails *details.Details, upgradeOutcome UpgradeOutcome) error {
	if err := u.watcher.markUpgrade(u.log,
		dataPath,             // data dir to place the marker in
		newAgentInstall,      // new agent version data
		previousAgentInstall, // old agent version data
		action, upgradeDetails, upgradeOutcome); err != nil {

		return err
	}

	watcherExecutable := u.watcher.selectWatcherExecutable(topPath, previousAgentInstall, newAgentInstall)

	watcherCmd, err := u.watcher.invokeWatcher(u.log, watcherExecutable)
	if err != nil {
		return err
	}

	if err := u.watcher.waitForWatcher(ctx, u.log, markerFilePath, waitTime, createTimeoutContext); err != nil {
		return goerrors.Join(err, watcherCmd.Process.Kill())
	}

	return nil
}
