// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package upgrade

import (
	"context"
	goerrors "errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	filecopy "github.com/otiai10/copy"
	"go.elastic.co/apm/v2"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/filelock"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/reexec"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact/download"
	upgradeErrors "github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact/download/errors"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/details"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/ttl"
	"github.com/elastic/elastic-agent/internal/pkg/agent/configuration"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/internal/pkg/agent/install"
	"github.com/elastic/elastic-agent/internal/pkg/config"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi/acker"
	fleetclient "github.com/elastic/elastic-agent/internal/pkg/fleetapi/client"
	"github.com/elastic/elastic-agent/internal/pkg/release"
	"github.com/elastic/elastic-agent/pkg/control/v2/client"
	"github.com/elastic/elastic-agent/pkg/control/v2/cproto"
	"github.com/elastic/elastic-agent/pkg/core/logger"
	agtversion "github.com/elastic/elastic-agent/pkg/version"
	currentagtversion "github.com/elastic/elastic-agent/version"
)

const (
	AgentName          = "elastic-agent"
	HashLen            = 6
	agentCommitFile    = ".elastic-agent.active.commit"
	runDirMod          = 0770
	snapshotSuffix     = "-SNAPSHOT"
	watcherMaxWaitTime = 30 * time.Second
	fipsPrefix         = "-fips"
)

var agentArtifact = artifact.Artifact{
	Name:     "Elastic Agent",
	Cmd:      AgentName,
	Artifact: "beats/" + AgentName,
}

var (
	ErrWatcherNotStarted    = errors.New("watcher did not start in time")
	ErrUpgradeSameVersion   = errors.New("upgrade did not occur because it is the same version")
	ErrNonFipsToFips        = errors.New("cannot switch to fips mode when upgrading")
	ErrFipsToNonFips        = errors.New("cannot switch to non-fips mode when upgrading")
	ErrNilUpdateMarker      = errors.New("loaded a nil update marker")
	ErrEmptyRollbackVersion = errors.New("rollback version is empty")
	ErrNoRollbacksAvailable = errors.New("no rollbacks available")
	ErrAgentInstallNotFound = errors.New("agent install descriptor not found")
	// Version_9_3_0_SNAPSHOT is the minimum version for manual rollback and rollback reason
	Version_9_3_0_SNAPSHOT = agtversion.NewParsedSemVer(9, 3, 0, "SNAPSHOT", "")
)

func init() {
	if release.FIPSDistribution() {
		agentArtifact.Cmd += fipsPrefix
	}
}

type artifactDownloadHandler interface {
	downloadArtifact(ctx context.Context, parsedVersion *agtversion.ParsedSemVer, sourceURI string, upgradeDetails *details.Details, skipVerifyOverride, skipDefaultPgp bool, pgpBytes ...string) (_ string, err error)
	withFleetServerURI(fleetServerURI string)
}
type unpackHandler interface {
	unpack(version, archivePath, dataDir string, flavor string) (UnpackResult, error)
	getPackageMetadata(archivePath string) (packageMetadata, error)
}

// Types used to abstract copyActionStore, copyRunDirectory and github.com/otiai10/copy.Copy
type copyActionStoreFunc func(log *logger.Logger, newHome string) error
type copyRunDirectoryFunc func(log *logger.Logger, oldRunPath, newRunPath string) error
type fileDirCopyFunc func(from, to string, opts ...filecopy.Options) error
type markUpgradeFunc func(log *logger.Logger, dataDirPath string, updatedOn time.Time, agent, previousAgent agentInstall, action *fleetapi.ActionUpgrade, upgradeDetails *details.Details, availableRollbacks map[string]ttl.TTLMarker) error
type changeSymlinkFunc func(log *logger.Logger, topDirPath, symlinkPath, newTarget string) error
type rollbackInstallFunc func(ctx context.Context, log *logger.Logger, topDirPath, versionedHome, oldVersionedHome string, rollbackSource availableRollbacksSource) error

// Types used to abstract stdlib functions
type mkdirAllFunc func(name string, perm fs.FileMode) error
type readFileFunc func(name string) ([]byte, error)
type writeFileFunc func(name string, data []byte, perm fs.FileMode) error

// WatcherHelper is an abstraction of operations that Upgrader will trigger on elastic-agent watcher.
// This is defined to help with Upgrader testing and verify interactions with elastic-agent watcher
type WatcherHelper interface {
	// InvokeWatcher invokes an elastic-agent watcher using the agentExecutable passed as argument
	InvokeWatcher(log *logger.Logger, agentExecutable string, additionalWatchArgs ...string) (*exec.Cmd, error)
	// SelectWatcherExecutable will return the path to the newer elastic-agent executable that will be used to invoke the
	// more recent watcher between the previous (the agent that started the upgrade) and current (the agent that will run after restart)
	// agent installation
	SelectWatcherExecutable(topDir string, previous agentInstall, current agentInstall) string
	// WaitForWatcher will listen for changes to the update marker, waiting for the elastic-agent watcher to set UPG_WATCHING state
	// in the upgrade details' metadata
	WaitForWatcher(ctx context.Context, log *logger.Logger, markerFilePath string, waitTime time.Duration) error
	// TakeOverWatcher will look for watcher processes and terminate them while at the same time trying to acquire the watcher AppLocker.
	// It will return once it managed to get the AppLocker or with an error if the lock could not be acquired.
	TakeOverWatcher(ctx context.Context, log *logger.Logger, topDir string) (*filelock.AppLocker, error)
}

type availableRollbacksSource interface {
	Set(map[string]ttl.TTLMarker) error
	Get() (map[string]ttl.TTLMarker, error)
}

// Upgrader performs an upgrade
type Upgrader struct {
	log                      *logger.Logger
	settings                 *artifact.Config
	upgradeSettings          *configuration.UpgradeConfig
	agentInfo                info.Agent
	upgradeable              bool
	fleetServerURI           string
	markerWatcher            MarkerWatcher
	watcherHelper            WatcherHelper
	availableRollbacksSource availableRollbacksSource

	// The following are abstractions for testability
	artifactDownloader   artifactDownloadHandler
	unpacker             unpackHandler
	isDiskSpaceErrorFunc func(err error) bool
	extractAgentVersion  func(metadata packageMetadata, upgradeVersion string) agentVersion
	copyActionStore      copyActionStoreFunc
	copyRunDirectory     copyRunDirectoryFunc
	markUpgrade          markUpgradeFunc
	changeSymlink        changeSymlinkFunc
	rollbackInstall      rollbackInstallFunc
}

// IsUpgradeable when agent is installed and running as a service or flag was provided.
func IsUpgradeable() bool {
	// only upgradeable if running from Agent installer and running under the
	// control of the system supervisor (or built specifically with upgrading enabled)
	return release.Upgradeable() || (paths.RunningInstalled() && info.RunningUnderSupervisor())
}

// NewUpgrader creates an upgrader which is capable of performing upgrade operation
func NewUpgrader(log *logger.Logger, settings *artifact.Config, upgradeConfig *configuration.UpgradeConfig, agentInfo info.Agent, watcherHelper WatcherHelper, ars availableRollbacksSource) (*Upgrader, error) {
	return &Upgrader{
		log:                      log,
		settings:                 settings,
		upgradeSettings:          upgradeConfig,
		agentInfo:                agentInfo,
		upgradeable:              IsUpgradeable(),
		markerWatcher:            newMarkerFileWatcher(markerFilePath(paths.Data()), log),
		watcherHelper:            watcherHelper,
		availableRollbacksSource: ars,
		artifactDownloader:       newArtifactDownloader(settings, log),
		unpacker:                 newUnpacker(log),
		isDiskSpaceErrorFunc:     upgradeErrors.IsDiskSpaceError,
		extractAgentVersion:      extractAgentVersion,
		copyActionStore:          copyActionStoreProvider(os.ReadFile, os.WriteFile),
		copyRunDirectory:         copyRunDirectoryProvider(os.MkdirAll, filecopy.Copy),
		markUpgrade:              markUpgradeProvider(UpdateActiveCommit, os.WriteFile),
		changeSymlink:            changeSymlink,
		rollbackInstall:          rollbackInstall,
	}, nil
}

// SetClient reloads URI based on up to date fleet client
func (u *Upgrader) SetClient(c fleetclient.Sender) {
	if c == nil {
		u.log.Debug("client nil, resetting Fleet Server URI")
		u.fleetServerURI = ""
		u.artifactDownloader.withFleetServerURI("")
	}

	u.fleetServerURI = c.URI()
	u.log.Debugf("Set client changed URI to %s", u.fleetServerURI)
	u.artifactDownloader.withFleetServerURI(u.fleetServerURI)
}

// Reload reloads the artifact configuration for the upgrader.
// As of today, December 2023, fleet-server does not send most of the configuration
// defined in artifact.Config, what will likely change in the near future.
func (u *Upgrader) Reload(rawConfig *config.Config) error {
	cfg, err := configuration.NewFromConfig(rawConfig)
	if err != nil {
		return fmt.Errorf("invalid config: %w", err)
	}

	// the source URI coming from fleet which uses a different naming.
	type fleetCfg struct {
		// FleetSourceURI: source of the artifacts, e.g https://artifacts.elastic.co/downloads/
		FleetSourceURI string `json:"agent.download.source_uri" config:"agent.download.source_uri"`
	}
	fleetSourceURI := &fleetCfg{}
	if err := rawConfig.UnpackTo(&fleetSourceURI); err != nil {
		return errors.New(err, "failed to unpack config during reload")
	}

	// fleet configuration takes precedence
	if fleetSourceURI.FleetSourceURI != "" {
		cfg.Settings.DownloadConfig.SourceURI = fleetSourceURI.FleetSourceURI
	}

	if cfg.Settings.DownloadConfig.SourceURI != "" {
		u.log.Infof("Source URI changed from %q to %q",
			u.settings.SourceURI,
			cfg.Settings.DownloadConfig.SourceURI)
	} else {
		// source uri unset, reset to default
		u.log.Infof("Source URI reset from %q to %q",
			u.settings.SourceURI,
			artifact.DefaultSourceURI)
		cfg.Settings.DownloadConfig.SourceURI = artifact.DefaultSourceURI
	}

	u.settings = cfg.Settings.DownloadConfig
	u.upgradeSettings = cfg.Settings.Upgrade

	u.artifactDownloader = newArtifactDownloader(u.settings, u.log)

	return nil
}

// Upgradeable returns true if the Elastic Agent can be upgraded.
func (u *Upgrader) Upgradeable() bool {
	return u.upgradeable
}

type agentVersion struct {
	version  string
	snapshot bool
	hash     string
	fips     bool
}

func (av agentVersion) String() string {
	buf := strings.Builder{}
	buf.WriteString(av.version)
	if av.snapshot {
		buf.WriteString(snapshotSuffix)
	}
	buf.WriteString(" (hash: ")
	buf.WriteString(av.hash)
	buf.WriteString(")")
	return buf.String()
}

func checkUpgrade(log *logger.Logger, currentVersion, newVersion agentVersion, metadata packageMetadata) error {
	// Compare the downloaded version (including git hash) to see if we need to upgrade
	// versions are the same if the numbers and hash match which may occur in a SNAPSHOT -> SNAPSHOT upgrage
	same := isSameVersion(log, currentVersion, newVersion)
	if same {
		log.Warnf("Upgrade action skipped because agent is already at version %s", currentVersion)
		return ErrUpgradeSameVersion
	}

	if currentVersion.fips && !metadata.manifest.Package.Fips {
		log.Warnf("Upgrade action skipped because FIPS-capable Agent cannot be upgraded to non-FIPS-capable Agent")
		return ErrFipsToNonFips
	}

	if !currentVersion.fips && metadata.manifest.Package.Fips {
		log.Warnf("Upgrade action skipped because non-FIPS-capable Agent cannot be upgraded to FIPS-capable Agent")
		return ErrNonFipsToFips
	}

	return nil
}

// Upgrade upgrades running agent, function returns shutdown callback that must be called by reexec.
func (u *Upgrader) Upgrade(ctx context.Context, version string, rollback bool, sourceURI string, action *fleetapi.ActionUpgrade, det *details.Details, skipVerifyOverride bool, skipDefaultPgp bool, pgpBytes ...string) (_ reexec.ShutdownCallbackFn, err error) {

	if rollback {
		return u.rollbackToPreviousVersion(ctx, paths.Top(), time.Now(), version, action)
	}

	u.log.Infow("Upgrading agent", "version", version, "source_uri", sourceURI)
	cleanupPaths := []string{}
	defer func() {
		if err != nil {
			// Add the disk space error to the error chain if it is a disk space error
			// so that we can use errors.Is to check for it
			if u.isDiskSpaceErrorFunc(err) {
				err = goerrors.Join(err, upgradeErrors.ErrInsufficientDiskSpace)
			}
			// If there is an error, we need to clean up downloads and any
			// extracted agent files.
			for _, path := range cleanupPaths {
				rmErr := os.RemoveAll(path)
				if rmErr != nil {
					u.log.Errorw("error removing path during upgrade cleanup", "error.message", rmErr, "path", path)
					err = goerrors.Join(err, rmErr)
				}
			}
		}
	}()

	currentVersion := agentVersion{
		version:  release.Version(),
		snapshot: release.Snapshot(),
		hash:     release.Commit(),
		fips:     release.FIPSDistribution(),
	}

	// Compare versions and exit before downloading anything if the upgrade
	// is for the same release version that is currently running
	if isSameReleaseVersion(u.log, currentVersion, version) {
		u.log.Warnf("Upgrade action skipped because agent is already at version %s", currentVersion)
		return nil, ErrUpgradeSameVersion
	}

	// Inform the Upgrade Marker Watcher that we've started upgrading. Note that this
	// is only possible to do in-memory since, today, the  process that's initiating
	// the upgrade is the same as the Agent process in which the Upgrade Marker Watcher is
	// running. If/when, in the future, the process initiating the upgrade is separated
	// from the Agent process in which the Upgrade Marker Watcher is running, such in-memory
	// communication will need to be replaced with inter-process communication (e.g. via
	// a file, e.g. the Upgrade Marker file or something else).
	u.markerWatcher.SetUpgradeStarted()

	span, ctx := apm.StartSpan(ctx, "upgrade", "app.internal")
	defer span.End()

	err = cleanNonMatchingVersionsFromDownloads(u.log, u.agentInfo.Version())
	if err != nil {
		u.log.Errorw("Unable to clean downloads before update", "error.message", err, "downloads.path", paths.Downloads())
	}

	det.SetState(details.StateDownloading)

	sourceURI = u.sourceURI(sourceURI)

	parsedVersion, err := agtversion.ParseVersion(version)
	if err != nil {
		return nil, fmt.Errorf("error parsing version %q: %w", version, err)
	}

	archivePath, err := u.artifactDownloader.downloadArtifact(ctx, parsedVersion, sourceURI, det, skipVerifyOverride, skipDefaultPgp, pgpBytes...)

	// If the artifactPath is not empty, then the artifact was downloaded.
	// There may still be an error in the download process, so we need to add
	// the archive and hash path to the cleanup slice.
	if archivePath != "" {
		archiveHashPath := download.AddHashExtension(archivePath)
		cleanupPaths = append(cleanupPaths, archivePath, archiveHashPath)
	}

	if err != nil {
		// Run the same pre-upgrade cleanup task to get rid of any newly downloaded files
		// This may have an issue if users are upgrading to the same version number.
		if dErr := cleanNonMatchingVersionsFromDownloads(u.log, u.agentInfo.Version()); dErr != nil {
			u.log.Errorw("Unable to remove file after verification failure", "error.message", dErr)
		}

		return nil, err
	}

	det.SetState(details.StateExtracting)

	metadata, err := u.unpacker.getPackageMetadata(archivePath)
	if err != nil {
		return nil, fmt.Errorf("reading metadata for elastic agent version %s package %q: %w", version, archivePath, err)
	}

	newVersion := u.extractAgentVersion(metadata, version)
	if err := checkUpgrade(u.log, currentVersion, newVersion, metadata); err != nil {
		return nil, fmt.Errorf("cannot upgrade the agent: %w", err)
	}

	u.log.Infow("Unpacking agent package", "version", newVersion)

	// Nice to have: add check that no archive files end up in the current versioned home
	// default to no flavor to avoid breaking behavior

	// no default flavor, keep everything in case flavor is not specified
	// in case of error fallback to keep-all
	detectedFlavor, err := install.UsedFlavor(paths.Top(), "")
	if err != nil {
		u.log.Warnf("error encountered when detecting used flavor with top path %q: %v", paths.Top(), err)
	}
	u.log.Debugf("detected used flavor: %q", detectedFlavor)
	unpackRes, err := u.unpacker.unpack(version, archivePath, paths.Data(), detectedFlavor)

	// If VersionedHome is empty then unpack has not started unpacking the
	// archive yet. There's nothing to clean up. Return the error.
	if unpackRes.VersionedHome == "" {
		return nil, goerrors.Join(err, fmt.Errorf("versionedhome is empty: %v", unpackRes))
	}

	// If VersionedHome is not empty, it means that the unpack function has
	// started extracting the archive. It may have failed while extracting.
	// Setup newHome to be cleanedup.
	newHome := filepath.Join(paths.Top(), unpackRes.VersionedHome)

	cleanupPaths = append(cleanupPaths, newHome)

	if err != nil {
		return nil, err
	}

	newHash := unpackRes.Hash
	if newHash == "" {
		return nil, errors.New("unknown hash")
	}

	if err := u.copyActionStore(u.log, newHome); err != nil {
		return nil, fmt.Errorf("failed to copy action store: %w", err)
	}

	newRunPath := filepath.Join(newHome, "run")
	oldRunPath := filepath.Join(paths.Run())

	if err := u.copyRunDirectory(u.log, oldRunPath, newRunPath); err != nil {
		return nil, fmt.Errorf("failed to copy run directory: %w", err)
	}

	det.SetState(details.StateReplacing)

	// create symlink to the <new versioned-home>/elastic-agent
	hashedDir := unpackRes.VersionedHome

	symlinkPath := filepath.Join(paths.Top(), AgentName)

	// paths.BinaryPath properly derives the binary directory depending on the platform. The path to the binary for macOS is inside of the app bundle.
	newPath := paths.BinaryPath(filepath.Join(paths.Top(), hashedDir), AgentName)

	currentVersionedHome, err := filepath.Rel(paths.Top(), paths.Home())
	if err != nil {
		return nil, fmt.Errorf("calculating home path relative to top, home: %q top: %q : %w", paths.Home(), paths.Top(), err)
	}

	if err := u.changeSymlink(u.log, paths.Top(), symlinkPath, newPath); err != nil {
		u.log.Errorw("Rolling back: changing symlink failed", "error.message", err)
		rollbackErr := u.rollbackInstall(ctx, u.log, paths.Top(), hashedDir, currentVersionedHome, u.availableRollbacksSource)
		return nil, goerrors.Join(err, rollbackErr)
	}

	rollbackWindow := disableRollbackWindow
	if u.upgradeSettings != nil && u.upgradeSettings.Rollback != nil {
		rollbackWindow = u.upgradeSettings.Rollback.Window
	}

	// We rotated the symlink successfully: prepare the current and previous agent installation details for the update marker
	// In update marker the `current` agent install is the one where the symlink is pointing (the new one we didn't start yet)
	// while the `previous` install is the currently executing elastic-agent that is no longer reachable via the symlink.
	// After the restart at the end of the function, everything lines up correctly.
	current := agentInstall{
		parsedVersion: parsedVersion,
		version:       version,
		hash:          unpackRes.Hash,
		versionedHome: unpackRes.VersionedHome,
	}

	previousParsedVersion := currentagtversion.GetParsedAgentPackageVersion()
	previous := agentInstall{
		parsedVersion: previousParsedVersion,
		version:       release.VersionWithSnapshot(),
		hash:          release.Commit(),
		versionedHome: currentVersionedHome,
	}

	availableRollbacks := getAvailableRollbacks(rollbackWindow, time.Now(), release.VersionWithSnapshot(), previousParsedVersion, currentVersionedHome, release.Commit())

	if err = u.availableRollbacksSource.Set(availableRollbacks); err != nil {
		u.log.Errorw("Rolling back: setting ttl markers failed", "error.message", err)
		rollbackErr := u.rollbackInstall(ctx, u.log, paths.Top(), hashedDir, currentVersionedHome, u.availableRollbacksSource)
		return nil, goerrors.Join(err, rollbackErr)
	}

	if err = u.markUpgrade(u.log,
		paths.Data(), // data dir to place the marker in
		time.Now(),
		current,  // new agent version data
		previous, // old agent version data
		action, det, availableRollbacks); err != nil {
		u.log.Errorw("Rolling back: marking upgrade failed", "error.message", err)
		rollbackErr := u.rollbackInstall(ctx, u.log, paths.Top(), hashedDir, currentVersionedHome, u.availableRollbacksSource)
		return nil, goerrors.Join(err, rollbackErr)
	}

	watcherExecutable := u.watcherHelper.SelectWatcherExecutable(paths.Top(), previous, current)

	var watcherCmd *exec.Cmd
	if watcherCmd, err = u.watcherHelper.InvokeWatcher(u.log, watcherExecutable); err != nil {
		u.log.Errorw("Rolling back: starting watcher failed", "error.message", err)
		rollbackErr := u.rollbackInstall(ctx, u.log, paths.Top(), hashedDir, currentVersionedHome, u.availableRollbacksSource)
		return nil, goerrors.Join(err, rollbackErr)
	}

	watcherWaitErr := u.watcherHelper.WaitForWatcher(ctx, u.log, markerFilePath(paths.Data()), watcherMaxWaitTime)
	if watcherWaitErr != nil {
		killWatcherErr := watcherCmd.Process.Kill()
		rollbackErr := u.rollbackInstall(ctx, u.log, paths.Top(), hashedDir, currentVersionedHome, u.availableRollbacksSource)
		return nil, goerrors.Join(watcherWaitErr, killWatcherErr, rollbackErr)
	}

	cb := shutdownCallback(u.log, paths.Home(), release.Version(), version, filepath.Join(paths.Top(), unpackRes.VersionedHome))

	// Clean everything from the downloads dir
	u.log.Infow("Removing downloads directory", "file.path", paths.Downloads())
	err = os.RemoveAll(paths.Downloads())
	if err != nil {
		u.log.Errorw("Unable to clean downloads after update", "error.message", err, "file.path", paths.Downloads())
	}

	return cb, nil
}

// Ack acks last upgrade action
func (u *Upgrader) Ack(ctx context.Context, acker acker.Acker) error {
	// get upgrade action
	marker, err := LoadMarker(paths.Data())
	if err != nil {
		return err
	}
	if marker == nil {
		return nil
	}

	if marker.Acked {
		return nil
	}

	// Action can be nil if the upgrade was called locally.
	// Should handle gracefully
	// https://github.com/elastic/elastic-agent/issues/1788
	if marker.Action != nil {
		if err := u.AckAction(ctx, acker, marker.Action); err != nil {
			return err
		}
	}

	marker.Acked = true

	return SaveMarker(paths.Data(), marker, false)
}

func (u *Upgrader) AckAction(ctx context.Context, acker acker.Acker, action fleetapi.Action) error {
	if acker == nil {
		return nil
	}

	if err := acker.Ack(ctx, action); err != nil {
		return err
	}

	if err := acker.Commit(ctx); err != nil {
		return err
	}

	return nil
}

func (u *Upgrader) MarkerWatcher() MarkerWatcher {
	return u.markerWatcher
}

func (u *Upgrader) sourceURI(retrievedURI string) string {
	if retrievedURI != "" {
		return retrievedURI
	}

	return u.settings.SourceURI
}

func extractAgentVersion(metadata packageMetadata, upgradeVersion string) agentVersion {
	newVersion := agentVersion{}
	if metadata.manifest != nil {
		packageDesc := metadata.manifest.Package
		newVersion.version = packageDesc.Version
		newVersion.snapshot = packageDesc.Snapshot
	} else {
		// extract version info from the version string (we can ignore parsing errors as it would have never passed the download step)
		parsedVersion, _ := agtversion.ParseVersion(upgradeVersion)
		newVersion.version, newVersion.snapshot = parsedVersion.ExtractSnapshotFromVersionString()
	}
	newVersion.hash = metadata.hash
	return newVersion
}

func isSameVersion(log *logger.Logger, current agentVersion, newVersion agentVersion) bool {
	log.Debugw("Comparing current and new agent version", "current_version", current, "new_version", newVersion)
	return current == newVersion
}

func rollbackInstall(ctx context.Context, log *logger.Logger, topDirPath, versionedHome, oldVersionedHome string, rollbackSource availableRollbacksSource) error {
	oldAgentPath := paths.BinaryPath(filepath.Join(topDirPath, oldVersionedHome), AgentName)
	err := changeSymlink(log, topDirPath, filepath.Join(topDirPath, AgentName), oldAgentPath)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("rolling back install: restoring symlink to %q failed: %w", oldAgentPath, err)
	}

	newAgentInstallPath := filepath.Join(topDirPath, versionedHome)
	err = os.RemoveAll(newAgentInstallPath)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("rolling back install: removing new agent install at %q failed: %w", newAgentInstallPath, err)
	}

	err = rollbackSource.Set(nil)
	if err != nil {
		return fmt.Errorf("rolling back install: error clearing ttl markers: %w", err)
	}

	return nil
}

func copyActionStoreProvider(readFile readFileFunc, writeFile writeFileFunc) copyActionStoreFunc {
	return func(log *logger.Logger, newHome string) error {
		// copies legacy action_store.yml, state.yml and state.enc encrypted file if exists
		storePaths := []string{paths.AgentActionStoreFile(), paths.AgentStateStoreYmlFile(), paths.AgentStateStoreFile()}
		log.Infow("Copying action store", "new_home_path", newHome)

		for _, currentActionStorePath := range storePaths {
			newActionStorePath := filepath.Join(newHome, filepath.Base(currentActionStorePath))
			log.Infow("Copying action store path", "from", currentActionStorePath, "to", newActionStorePath)
			// using readfile instead of os.ReadFile for testability
			currentActionStore, err := readFile(currentActionStorePath)
			if os.IsNotExist(err) {
				// nothing to copy
				continue
			}
			if err != nil {
				return err
			}

			// using writeFile instead of os.WriteFile for testability
			if err := writeFile(newActionStorePath, currentActionStore, 0o600); err != nil {
				return fmt.Errorf("failed to write action store at %q: %w", newActionStorePath, err)
			}
		}

		return nil
	}
}

func copyRunDirectoryProvider(mkdirAll mkdirAllFunc, fileDirCopy fileDirCopyFunc) copyRunDirectoryFunc {
	return func(log *logger.Logger, oldRunPath, newRunPath string) error {
		log.Infow("Copying run directory", "new_run_path", newRunPath, "old_run_path", oldRunPath)

		if err := mkdirAll(newRunPath, runDirMod); err != nil {
			return fmt.Errorf("failed to create run directory: %w", err)
		}

		err := copyDir(log, oldRunPath, newRunPath, true, fileDirCopy)
		if os.IsNotExist(err) {
			// nothing to copy, operation ok
			log.Infow("Run directory not present", "old_run_path", oldRunPath)
			return nil
		}
		if err != nil {
			return fmt.Errorf("failed to copy %q to %q: %w", oldRunPath, newRunPath, err)
		}

		return nil
	}
}

// shutdownCallback returns a callback function to be executing during shutdown once all processes are closed.
// this goes through runtime directory of agent and copies all the state files created by processes to new versioned
// home directory with updated process name to match new version.
func shutdownCallback(l *logger.Logger, homePath, prevVersion, newVersion, newHome string) reexec.ShutdownCallbackFn {
	if release.Snapshot() {
		// SNAPSHOT is part of newVersion
		prevVersion += snapshotSuffix
	}

	return func() error {
		runtimeDir := filepath.Join(homePath, "run")
		l.Debugf("starting copy of run directories from %q to %q", homePath, newHome)
		processDirs, err := readProcessDirs(runtimeDir)
		if err != nil {
			return err
		}

		oldHome := homePath
		for _, processDir := range processDirs {
			relPath, _ := filepath.Rel(oldHome, processDir)

			newRelPath := strings.ReplaceAll(relPath, prevVersion, newVersion)
			newRelPath = strings.ReplaceAll(newRelPath, oldHome, newHome)
			newDir := filepath.Join(newHome, newRelPath)
			l.Debugf("copying %q -> %q", processDir, newDir)
			if err := copyDir(l, processDir, newDir, true, filecopy.Copy); err != nil {
				return err
			}
		}
		return nil
	}
}

func readProcessDirs(runtimeDir string) ([]string, error) {
	pipelines, err := readDirs(runtimeDir)
	if err != nil {
		return nil, err
	}

	processDirs := make([]string, 0)
	for _, p := range pipelines {
		dirs, err := readDirs(p)
		if err != nil {
			return nil, err
		}

		processDirs = append(processDirs, dirs...)
	}

	return processDirs, nil
}

// readDirs returns list of absolute paths to directories inside specified path.
func readDirs(dir string) ([]string, error) {
	dirEntries, err := os.ReadDir(dir)
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}

	dirs := make([]string, 0, len(dirEntries))
	for _, de := range dirEntries {
		if !de.IsDir() {
			continue
		}

		dirs = append(dirs, filepath.Join(dir, de.Name()))
	}

	return dirs, nil
}

func copyDir(l *logger.Logger, from, to string, ignoreErrs bool, fileDirCopy fileDirCopyFunc) error {
	var onErr func(src, dst string, err error) error

	if ignoreErrs {
		onErr = func(src, dst string, err error) error {
			if err == nil {
				return nil
			}

			// ignore all errors, just log them
			l.Infof("ignoring error: failed to copy %q to %q: %s", src, dst, err.Error())
			return nil
		}
	}

	// Try to detect if we are running with SSDs. If we are increase the copy concurrency,
	// otherwise fall back to the default.
	copyConcurrency := 1
	hasSSDs, detectHWErr := install.HasAllSSDs()
	if detectHWErr != nil {
		l.Infow("Could not determine block storage type, disabling copy concurrency", "error.message", detectHWErr)
	}
	if hasSSDs {
		copyConcurrency = runtime.NumCPU() * 4
	}

	return fileDirCopy(from, to, filecopy.Options{
		OnSymlink: func(_ string) filecopy.SymlinkAction {
			return filecopy.Shallow
		},
		Sync:         true,
		OnError:      onErr,
		NumOfWorkers: int64(copyConcurrency),
	})
}

// IsInProgress checks if an Elastic Agent upgrade is already in progress. It
// returns true if so and false if not.
// `c client.Client` is expected to be a connected client.
func IsInProgress(c client.Client, watcherPIDsFetcher func() ([]int, error)) (bool, error) {
	// First we check if any Upgrade Watcher processes are running. If they are,
	// it means an upgrade is in progress. We check this before checking the Elastic
	// Agent's status because the Elastic Agent GRPC server may briefly be
	// unavailable during an upgrade and so the client connection might fail.
	watcherPIDs, err := watcherPIDsFetcher()
	if err != nil {
		return false, fmt.Errorf("failed to determine if upgrade watcher is running: %w", err)
	}
	if len(watcherPIDs) > 0 {
		return true, nil
	}

	// Next we check the Elastic Agent's status using the GRPC client.
	state, err := c.State(context.Background())
	if err != nil {
		return false, fmt.Errorf("failed to get agent state: %w", err)
	}

	return state.State == cproto.State_UPGRADING, nil
}

// isSameReleaseVersion will return true if upgradeVersion and currentVersion are equal using only release numbers and SNAPSHOT prerelease qualifiers.
// They are not equal if either are a SNAPSHOT, or if the semver numbers (including prerelease and build identifiers) differ.
func isSameReleaseVersion(log *logger.Logger, current agentVersion, upgradeVersion string) bool {
	if current.snapshot {
		return false
	}
	target, err := agtversion.ParseVersion(upgradeVersion)
	if err != nil {
		log.Warnw("Unable too parse version for released version comparison", upgradeVersion, err)
		return false
	}
	targetVersion, targetSnapshot := target.ExtractSnapshotFromVersionString()
	if targetSnapshot {
		return false
	}
	return current.version == targetVersion
}
