// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package upgrade

import (
	"context"
	goerrors "errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"go.elastic.co/apm/v2"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/reexec"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact/download"
	fsDownloader "github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact/download/fs"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/details"
	upgradeErrors "github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/errors"
	"github.com/elastic/elastic-agent/internal/pkg/agent/configuration"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
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
	agentName                 = "elastic-agent"
	hashLen                   = 6
	agentCommitFile           = ".elastic-agent.active.commit"
	runDirMod                 = 0770
	snapshotSuffix            = "-SNAPSHOT"
	watcherMaxWaitTime        = 30 * time.Second
	fipsPrefix                = "-fips"
	fileDownloaderFactory     = "fileDownloaderFactory"
	composedDownloaderFactory = "composedDownloaderFactory"
)

var agentArtifact = artifact.Artifact{
	Name:     "Elastic Agent",
	Cmd:      agentName,
	Artifact: "beats/" + agentName,
}

var (
	ErrWatcherNotStarted  = errors.New("watcher did not start in time")
	ErrUpgradeSameVersion = errors.New("upgrade did not occur because it is the same version")
	ErrNonFipsToFips      = errors.New("cannot switch to fips mode when upgrading")
	ErrFipsToNonFips      = errors.New("cannot switch to non-fips mode when upgrading")
)

func init() {
	if release.FIPSDistribution() {
		agentArtifact.Cmd += fipsPrefix
	}
}

type downloaderFactory func(*agtversion.ParsedSemVer, *logger.Logger, *artifact.Config, *details.Details) (download.Downloader, error)

type DownloaderFactoryProvider interface {
	GetDownloaderFactory(name string) (downloaderFactory, error)
}

type downloaderFactoryProvider struct {
	downloaderFactories map[string]downloaderFactory
}

func (d *downloaderFactoryProvider) GetDownloaderFactory(name string) (downloaderFactory, error) {
	factory, ok := d.downloaderFactories[name]
	if !ok {
		return nil, fmt.Errorf("downloader factory %q not found", name)
	}
	return factory, nil
}

type upgradeCleaner interface {
	setupSymlinkCleanup(symlinkFunc changeSymlinkFunc, topDirPath, oldVersionedHome, agentName string) error
	setupArchiveCleanup(downloadResult download.DownloadResult) error
	setupUnpackCleanup(newHomeDir, oldHomeDir string) error
	cleanup(err error) error
}

type checkUpgradeFn func(log *logger.Logger, currentVersion, newVersion agentVersion, metadata packageMetadata) error

type upgradeExecutor interface {
	downloadArtifact(ctx context.Context, parsedTargetVersion *agtversion.ParsedSemVer, agentInfo info.Agent, sourceURI string, fleetServerURI string, upgradeDetails *details.Details, skipVerifyOverride, skipDefaultPgp bool, pgpBytes ...string) (download.DownloadResult, error)
	unpackArtifact(downloadResult download.DownloadResult, version, archivePath, topPath, flavor, dataPath, currentHome string, upgradeDetails *details.Details, currentVersion agentVersion, checkUpgradeFn checkUpgradeFn) (unpackStepResult, error)
	replaceOldWithNew(unpackStepResult unpackStepResult, currentVersionedHome, topPath, agentName, oldRunPath, newRunPath, symlinkPath, newBinPath string, upgradeDetails *details.Details) error
	watchNewAgent(ctx context.Context, markerFilePath, topPath, dataPath string, waitTime time.Duration, createTimeoutContext createContextWithTimeout, newAgentInstall agentInstall, previousAgentInstall agentInstall, action *fleetapi.ActionUpgrade, upgradeDetails *details.Details, upgradeOutcome UpgradeOutcome) error
}

// Upgrader performs an upgrade
type Upgrader struct {
	log             *logger.Logger
	settings        *artifact.Config
	agentInfo       info.Agent
	upgradeable     bool
	fleetServerURI  string
	markerWatcher   MarkerWatcher
	upgradeCleaner  upgradeCleaner
	upgradeExecutor upgradeExecutor
}

// IsUpgradeable when agent is installed and running as a service or flag was provided.
func IsUpgradeable() bool {
	// only upgradeable if running from Agent installer and running under the
	// control of the system supervisor (or built specifically with upgrading enabled)
	return release.Upgradeable() || (paths.RunningInstalled() && info.RunningUnderSupervisor())
}

// NewUpgrader creates an upgrader which is capable of performing upgrade operation
func NewUpgrader(log *logger.Logger, settings *artifact.Config, agentInfo info.Agent) (*Upgrader, error) {
	downloaderFactories := map[string]downloaderFactory{
		fileDownloaderFactory: func(ver *agtversion.ParsedSemVer, l *logger.Logger, config *artifact.Config, d *details.Details) (download.Downloader, error) {
			return fsDownloader.NewDownloader(config), nil
		},
		composedDownloaderFactory: newDownloader,
	}

	downloaderFactoryProvider := &downloaderFactoryProvider{
		downloaderFactories: downloaderFactories,
	}

	upgradeCleaner := &upgradeCleanup{
		log:          log,
		cleanupFuncs: []func() error{},
	}

	return &Upgrader{
		log:            log,
		settings:       settings,
		agentInfo:      agentInfo,
		upgradeable:    IsUpgradeable(),
		markerWatcher:  newMarkerFileWatcher(markerFilePath(paths.Data()), log),
		upgradeCleaner: upgradeCleaner,
		upgradeExecutor: &executeUpgrade{
			log:                log,
			upgradeCleaner:     upgradeCleaner,
			artifactDownloader: newUpgradeArtifactDownloader(log, settings, downloaderFactoryProvider),
			unpacker:           &upgradeUnpacker{log: log},
			relinker:           &upgradeRelinker{},
			watcher:            &upgradeWatcher{},
			directoryCopier:    &directoryCopier{},
			diskSpaceErrorFunc: upgradeErrors.ToDiskSpaceErrorFunc(log),
		},
	}, nil
}

// SetClient reloads URI based on up to date fleet client
func (u *Upgrader) SetClient(c fleetclient.Sender) {
	if c == nil {
		u.log.Debug("client nil, resetting Fleet Server URI")
		u.fleetServerURI = ""
	}

	u.fleetServerURI = c.URI()
	u.log.Debugf("Set client changed URI to %s", u.fleetServerURI)
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
func (u *Upgrader) Upgrade(ctx context.Context, version string, sourceURI string, action *fleetapi.ActionUpgrade, det *details.Details, skipVerifyOverride bool, skipDefaultPgp bool, pgpBytes ...string) (_ reexec.ShutdownCallbackFn, err error) {
	defer func() {
		cleanupErr := u.upgradeCleaner.cleanup(err)
		if cleanupErr != nil {
			u.log.Errorf("Error cleaning up after upgrade: %w", cleanupErr)
			err = goerrors.Join(err, cleanupErr)
		}
	}()

	u.log.Infow("Upgrading agent", "version", version, "source_uri", sourceURI)

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

	sourceURI = u.sourceURI(sourceURI)

	parsedTargetVersion, err := agtversion.ParseVersion(version)
	if err != nil {
		return nil, fmt.Errorf("error parsing version %q: %w", version, err)
	}

	downloadResult, err := u.upgradeExecutor.downloadArtifact(ctx, parsedTargetVersion, u.agentInfo, sourceURI, u.fleetServerURI, det, skipVerifyOverride, skipDefaultPgp, pgpBytes...)
	if err != nil {
		return nil, err
	}

	unpackRes, err := u.upgradeExecutor.unpackArtifact(downloadResult, version, downloadResult.ArtifactPath, paths.Top(), "", paths.Data(), paths.Home(), det, currentVersion, checkUpgrade)
	if err != nil {
		return nil, err
	}

	newRunPath := filepath.Join(unpackRes.newHome, "run")
	oldRunPath := filepath.Join(paths.Run())

	symlinkPath := filepath.Join(paths.Top(), agentName)
	u.log.Infof("symlinkPath: %s", symlinkPath)

	// paths.BinaryPath properly derives the binary directory depending on the platform. The path to the binary for macOS is inside of the app bundle.
	newPath := paths.BinaryPath(filepath.Join(paths.Top(), unpackRes.VersionedHome), agentName)
	u.log.Infof("newPath: %s", newPath)

	currentVersionedHome, err := filepath.Rel(paths.Top(), paths.Home())
	if err != nil {
		return nil, fmt.Errorf("calculating home path relative to top, home: %q top: %q : %w", paths.Home(), paths.Top(), err)
	}

	err = u.upgradeExecutor.replaceOldWithNew(unpackRes, currentVersionedHome, paths.Top(), agentName, oldRunPath, newRunPath, symlinkPath, newPath, det)
	if err != nil {
		return nil, err
	}

	// We rotated the symlink successfully: prepare the current and previous agent installation details for the update marker
	// In update marker the `current` agent install is the one where the symlink is pointing (the new one we didn't start yet)
	// while the `previous` install is the currently executing elastic-agent that is no longer reachable via the symlink.
	// After the restart at the end of the function, everything lines up correctly.
	current := agentInstall{
		parsedVersion: parsedTargetVersion,
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

	err = u.upgradeExecutor.watchNewAgent(ctx, markerFilePath(paths.Data()), paths.Top(), paths.Data(), watcherMaxWaitTime, context.WithTimeout, current, previous, action, det, OUTCOME_UPGRADE)
	if err != nil {
		return nil, err
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

func isSameVersion(log *logger.Logger, current agentVersion, newVersion agentVersion) bool {
	log.Debugw("Comparing current and new agent version", "current_version", current, "new_version", newVersion)
	return current == newVersion
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
			if err := copyDir(l, processDir, newDir, true); err != nil {
				return err
			}
		}
		return nil
	}
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
