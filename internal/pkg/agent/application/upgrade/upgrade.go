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

	"github.com/otiai10/copy"
	"go.elastic.co/apm/v2"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/reexec"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/details"
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
	agentName          = "elastic-agent"
	hashLen            = 6
	agentCommitFile    = ".elastic-agent.active.commit"
	runDirMod          = 0770
	snapshotSuffix     = "-SNAPSHOT"
	watcherMaxWaitTime = 30 * time.Second
)

var agentArtifact = artifact.Artifact{
	Name:     "Elastic Agent",
	Cmd:      agentName,
	Artifact: "beats/" + agentName,
}

var ErrWatcherNotStarted = errors.New("watcher did not start in time")
var ErrUpgradeSameVersion = errors.New("upgrade did not occur because it is the same version")

// Upgrader performs an upgrade
type Upgrader struct {
	log            *logger.Logger
	settings       *artifact.Config
	agentInfo      info.Agent
	upgradeable    bool
	fleetServerURI string
	markerWatcher  MarkerWatcher
}

// IsUpgradeable when agent is installed and running as a service or flag was provided.
func IsUpgradeable() bool {
	// only upgradeable if running from Agent installer and running under the
	// control of the system supervisor (or built specifically with upgrading enabled)
	return release.Upgradeable() || (paths.RunningInstalled() && info.RunningUnderSupervisor())
}

// NewUpgrader creates an upgrader which is capable of performing upgrade operation
func NewUpgrader(log *logger.Logger, settings *artifact.Config, agentInfo info.Agent) (*Upgrader, error) {
	return &Upgrader{
		log:           log,
		settings:      settings,
		agentInfo:     agentInfo,
		upgradeable:   IsUpgradeable(),
		markerWatcher: newMarkerFileWatcher(markerFilePath(paths.Data()), log),
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

// Upgrade upgrades running agent, function returns shutdown callback that must be called by reexec.
func (u *Upgrader) Upgrade(ctx context.Context, version string, sourceURI string, action *fleetapi.ActionUpgrade, det *details.Details, skipVerifyOverride bool, skipDefaultPgp bool, pgpBytes ...string) (_ reexec.ShutdownCallbackFn, err error) {
	u.log.Infow("Upgrading agent", "version", version, "source_uri", sourceURI)

	currentVersion := agentVersion{
		version:  release.Version(),
		snapshot: release.Snapshot(),
		hash:     release.Commit(),
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

	archivePath, err := u.downloadArtifact(ctx, parsedVersion, sourceURI, det, skipVerifyOverride, skipDefaultPgp, pgpBytes...)
	if err != nil {
		// Run the same pre-upgrade cleanup task to get rid of any newly downloaded files
		// This may have an issue if users are upgrading to the same version number.
		if dErr := cleanNonMatchingVersionsFromDownloads(u.log, u.agentInfo.Version()); dErr != nil {
			u.log.Errorw("Unable to remove file after verification failure", "error.message", dErr)
		}

		return nil, err
	}

	det.SetState(details.StateExtracting)

	metadata, err := u.getPackageMetadata(archivePath)
	if err != nil {
		return nil, fmt.Errorf("reading metadata for elastic agent version %s package %q: %w", version, archivePath, err)
	}

	// Compare the downloaded version (including git hash) to see if we need to upgrade
	// versions are the same if the numbers and hash match which may occur in a SNAPSHOT -> SNAPSHOT upgrage
	same, newVersion := isSameVersion(u.log, currentVersion, metadata, version)
	if same {
		u.log.Warnf("Upgrade action skipped because agent is already at version %s", currentVersion)
		return nil, ErrUpgradeSameVersion
	}

	u.log.Infow("Unpacking agent package", "version", newVersion)

	// Nice to have: add check that no archive files end up in the current versioned home
	// default to no flavor to avoid breaking behavior

	// no default flavor, keep everything in case flavor is not specified
	// in case of error fallback to keep-all
	detectedFlavor, err := install.UsedFlavor(paths.Top(), "")
	if err != nil {
		u.log.Warnf("error encountered when detecting used flavor with top path %q: %w", paths.Top(), err)
	}
	u.log.Debugf("detected used flavor: %q", detectedFlavor)
	unpackRes, err := u.unpack(version, archivePath, paths.Data(), detectedFlavor)
	if err != nil {
		return nil, err
	}

	newHash := unpackRes.Hash
	if newHash == "" {
		return nil, errors.New("unknown hash")
	}

	if unpackRes.VersionedHome == "" {
		return nil, fmt.Errorf("versionedhome is empty: %v", unpackRes)
	}

	newHome := filepath.Join(paths.Top(), unpackRes.VersionedHome)

	if err := copyActionStore(u.log, newHome); err != nil {
		return nil, errors.New(err, "failed to copy action store")
	}

	newRunPath := filepath.Join(newHome, "run")
	oldRunPath := filepath.Join(paths.Home(), "run")

	if err := copyRunDirectory(u.log, oldRunPath, newRunPath); err != nil {
		return nil, errors.New(err, "failed to copy run directory")
	}

	det.SetState(details.StateReplacing)

	// create symlink to the <new versioned-home>/elastic-agent
	hashedDir := unpackRes.VersionedHome

	symlinkPath := filepath.Join(paths.Top(), agentName)

	// paths.BinaryPath properly derives the binary directory depending on the platform. The path to the binary for macOS is inside of the app bundle.
	newPath := paths.BinaryPath(filepath.Join(paths.Top(), hashedDir), agentName)

	currentVersionedHome, err := filepath.Rel(paths.Top(), paths.Home())
	if err != nil {
		return nil, fmt.Errorf("calculating home path relative to top, home: %q top: %q : %w", paths.Home(), paths.Top(), err)
	}

	if err := changeSymlink(u.log, paths.Top(), symlinkPath, newPath); err != nil {
		u.log.Errorw("Rolling back: changing symlink failed", "error.message", err)
		rollbackErr := rollbackInstall(ctx, u.log, paths.Top(), hashedDir, currentVersionedHome)
		return nil, goerrors.Join(err, rollbackErr)
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

	if err := markUpgrade(u.log,
		paths.Data(), // data dir to place the marker in
		current,      // new agent version data
		previous,     // old agent version data
		action, det); err != nil {
		u.log.Errorw("Rolling back: marking upgrade failed", "error.message", err)
		rollbackErr := rollbackInstall(ctx, u.log, paths.Top(), hashedDir, currentVersionedHome)
		return nil, goerrors.Join(err, rollbackErr)
	}

	var watcherExecutable = selectWatcherExecutable(paths.Top(), previous, current)

	var watcherCmd *exec.Cmd
	if watcherCmd, err = InvokeWatcher(u.log, watcherExecutable); err != nil {
		u.log.Errorw("Rolling back: starting watcher failed", "error.message", err)
		rollbackErr := rollbackInstall(ctx, u.log, paths.Top(), hashedDir, currentVersionedHome)
		return nil, goerrors.Join(err, rollbackErr)
	}

	watcherWaitErr := waitForWatcher(ctx, u.log, markerFilePath(paths.Data()), watcherMaxWaitTime)
	if watcherWaitErr != nil {
		killWatcherErr := watcherCmd.Process.Kill()
		rollbackErr := rollbackInstall(ctx, u.log, paths.Top(), hashedDir, currentVersionedHome)
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

func selectWatcherExecutable(topDir string, previous agentInstall, current agentInstall) string {
	// check if the upgraded version is less than the previous (currently installed) version
	if current.parsedVersion.Less(*previous.parsedVersion) {
		// use the current agent executable for watch, if downgrading the old agent doesn't understand the current agent's path structure.
		return paths.BinaryPath(filepath.Join(topDir, previous.versionedHome), agentName)
	} else {
		// use the new agent executable as it should be able to parse the new update marker
		return paths.BinaryPath(filepath.Join(topDir, current.versionedHome), agentName)
	}
}

func waitForWatcher(ctx context.Context, log *logger.Logger, markerFilePath string, waitTime time.Duration) error {
	return waitForWatcherWithTimeoutCreationFunc(ctx, log, markerFilePath, waitTime, context.WithTimeout)
}

type createContextWithTimeout func(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc)

func waitForWatcherWithTimeoutCreationFunc(ctx context.Context, log *logger.Logger, markerFilePath string, waitTime time.Duration, createTimeoutContext createContextWithTimeout) error {
	// Wait for the watcher to be up and running
	watcherContext, cancel := createTimeoutContext(ctx, waitTime)
	defer cancel()

	markerWatcher := newMarkerFileWatcher(markerFilePath, log)
	err := markerWatcher.Run(watcherContext)
	if err != nil {
		return fmt.Errorf("error starting update marker watcher: %w", err)
	}

	log.Infof("waiting up to %s for upgrade watcher to set %s state in upgrade marker", waitTime, details.StateWatching)

	for {
		select {
		case updMarker := <-markerWatcher.Watch():
			if updMarker.Details != nil && updMarker.Details.State == details.StateWatching {
				// watcher started and it is watching, all good
				log.Infof("upgrade watcher set %s state in upgrade marker: exiting wait loop", details.StateWatching)
				return nil
			}

		case <-watcherContext.Done():
			log.Error("upgrade watcher did not start watching within %s or context has expired", waitTime)
			return goerrors.Join(ErrWatcherNotStarted, watcherContext.Err())
		}
	}
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
		if err := acker.Ack(ctx, marker.Action); err != nil {
			return err
		}

		if err := acker.Commit(ctx); err != nil {
			return err
		}
	}

	marker.Acked = true

	return SaveMarker(marker, false)
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

func isSameVersion(log *logger.Logger, current agentVersion, metadata packageMetadata, upgradeVersion string) (bool, agentVersion) {
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

	log.Debugw("Comparing current and new agent version", "current_version", current, "new_version", newVersion)

	return current == newVersion, newVersion
}

func rollbackInstall(ctx context.Context, log *logger.Logger, topDirPath, versionedHome, oldVersionedHome string) error {
	oldAgentPath := paths.BinaryPath(filepath.Join(topDirPath, oldVersionedHome), agentName)
	err := changeSymlink(log, topDirPath, filepath.Join(topDirPath, agentName), oldAgentPath)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("rolling back install: restoring symlink to %q failed: %w", oldAgentPath, err)
	}

	newAgentInstallPath := filepath.Join(topDirPath, versionedHome)
	err = os.RemoveAll(newAgentInstallPath)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("rolling back install: removing new agent install at %q failed: %w", newAgentInstallPath, err)
	}
	return nil
}

func copyActionStore(log *logger.Logger, newHome string) error {
	// copies legacy action_store.yml, state.yml and state.enc encrypted file if exists
	storePaths := []string{paths.AgentActionStoreFile(), paths.AgentStateStoreYmlFile(), paths.AgentStateStoreFile()}
	log.Infow("Copying action store", "new_home_path", newHome)

	for _, currentActionStorePath := range storePaths {
		newActionStorePath := filepath.Join(newHome, filepath.Base(currentActionStorePath))
		log.Infow("Copying action store path", "from", currentActionStorePath, "to", newActionStorePath)
		currentActionStore, err := os.ReadFile(currentActionStorePath)
		if os.IsNotExist(err) {
			// nothing to copy
			continue
		}
		if err != nil {
			return err
		}

		if err := os.WriteFile(newActionStorePath, currentActionStore, 0o600); err != nil {
			return err
		}
	}

	return nil
}

func copyRunDirectory(log *logger.Logger, oldRunPath, newRunPath string) error {

	log.Infow("Copying run directory", "new_run_path", newRunPath, "old_run_path", oldRunPath)

	if err := os.MkdirAll(newRunPath, runDirMod); err != nil {
		return errors.New(err, "failed to create run directory")
	}

	err := copyDir(log, oldRunPath, newRunPath, true)
	if os.IsNotExist(err) {
		// nothing to copy, operation ok
		log.Infow("Run directory not present", "old_run_path", oldRunPath)
		return nil
	}
	if err != nil {
		return errors.New(err, "failed to copy %q to %q", oldRunPath, newRunPath)
	}

	return nil
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

func copyDir(l *logger.Logger, from, to string, ignoreErrs bool) error {
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

	return copy.Copy(from, to, copy.Options{
		OnSymlink: func(_ string) copy.SymlinkAction {
			return copy.Shallow
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
