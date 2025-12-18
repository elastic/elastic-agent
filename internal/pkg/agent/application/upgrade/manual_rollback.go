// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package upgrade

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/filelock"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/reexec"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/details"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/ttl"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi"
	"github.com/elastic/elastic-agent/internal/pkg/release"
	"github.com/elastic/elastic-agent/pkg/core/logger"
	"github.com/elastic/elastic-agent/pkg/version"
	agtversion "github.com/elastic/elastic-agent/version"
)

const disableRollbackWindow = time.Duration(0)

func (u *Upgrader) rollbackToPreviousVersion(ctx context.Context, topDir string, now time.Time, version string, action *fleetapi.ActionUpgrade) (reexec.ShutdownCallbackFn, error) {
	if version == "" {
		return nil, ErrEmptyRollbackVersion
	}

	// check that the upgrade marker exists and is accessible
	updateMarkerPath := markerFilePath(paths.DataFrom(topDir))
	_, err := os.Stat(updateMarkerPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("stat() on upgrade marker %q failed: %w", updateMarkerPath, err)
	}

	var watcherExecutable string
	var versionedHomeToRollbackTo string
	var updateMarkerExistsBeforeRollback bool

	if errors.Is(err, os.ErrNotExist) {
		// there is no upgrade marker (the rollback was requested after the watcher grace period had elapsed), we need
		// to extract available rollbacks from agent installs
		watcherExecutable, versionedHomeToRollbackTo, err = rollbackUsingAgentInstalls(u.log, u.watcherHelper, u.availableRollbacksSource, topDir, now, version, u.markUpgrade, action)
	} else {
		// If upgrade marker is available, we need to gracefully stop any watcher process, read the available rollbacks from
		// the upgrade marker and then proceed with rollback
		updateMarkerExistsBeforeRollback = true
		watcherExecutable, versionedHomeToRollbackTo, err = rollbackUsingUpgradeMarker(ctx, u.log, u.watcherHelper, topDir, now, version, action)
	}

	if err != nil {
		return nil, err
	}

	// rollback
	watcherCmd, err := u.watcherHelper.InvokeWatcher(u.log, watcherExecutable, "--rollback", versionedHomeToRollbackTo)
	if err != nil {
		if !updateMarkerExistsBeforeRollback {
			// best effort: cleanup the fake update marker
			cleanupErr := os.Remove(updateMarkerPath)
			if cleanupErr != nil {
				u.log.Errorf("Error cleaning up fake upgrade marker: %v", cleanupErr)
			}
		} else {
			// attempt to resume the  "normal" watcher to continue watching
			_, restoreWatcherErr := u.watcherHelper.InvokeWatcher(u.log, watcherExecutable)
			if restoreWatcherErr != nil {
				u.log.Errorf("Error resuming watch after rollback error : %v", restoreWatcherErr)
			}
		}

		return nil, fmt.Errorf("starting rollback command: %w", err)
	}

	u.log.Infof("rollback command started successfully, PID: %d", watcherCmd.Process.Pid)
	return nil, nil
}

func rollbackUsingAgentInstalls(log *logger.Logger, watcherHelper WatcherHelper, source availableRollbacksSource, topDir string, now time.Time, rollbackVersion string, markUpgrade markUpgradeFunc, action *fleetapi.ActionUpgrade) (string, string, error) {
	// read the available installs
	availableRollbacks, err := source.Get()
	if err != nil {
		return "", "", fmt.Errorf("retrieving available rollbacks: %w", err)
	}
	// check for the version we want to rollback to
	var targetInstall string
	var targetTTLMarker ttl.TTLMarker
	for versionedHome, ttlMarker := range availableRollbacks {
		if ttlMarker.Version == rollbackVersion && now.Before(ttlMarker.ValidUntil) {
			// found a valid target
			targetInstall = versionedHome
			targetTTLMarker = ttlMarker
			break
		}
	}

	if targetInstall == "" {
		return "", "", fmt.Errorf("version %q not listed among the available rollbacks: %w", rollbackVersion, ErrNoRollbacksAvailable)
	}

	if filepath.IsAbs(targetInstall) {
		targetInstall, err = filepath.Rel(topDir, targetInstall)
		if err != nil {
			return "", "", fmt.Errorf("error calculating path of install %q relative to %q: %w", targetInstall, topDir, err)
		}
	}

	prevAgentParsedVersion, err := version.ParseVersion(targetTTLMarker.Version)
	if err != nil {
		return "", "", fmt.Errorf("parsing version of target install %+v: %w", targetInstall, err)
	}

	// write out a fake upgrade marker to make the upgrade details state happy
	currentHome := paths.VersionedHome(topDir)
	relCurVersionedHome, err := filepath.Rel(topDir, currentHome)
	if err != nil {
		return "", "", fmt.Errorf("getting current install home path %q relative to top %q: %w", currentHome, topDir, err)
	}
	curAgentInstall := agentInstall{
		parsedVersion: agtversion.GetParsedAgentPackageVersion(),
		version:       release.VersionWithSnapshot(),
		hash:          release.Commit(),
		versionedHome: relCurVersionedHome,
	}

	prevAgentInstall := agentInstall{
		parsedVersion: prevAgentParsedVersion,
		version:       targetTTLMarker.Version,
		hash:          targetTTLMarker.Hash,
		versionedHome: targetInstall,
	}

	actionId := ""
	if action != nil {
		actionId = action.ActionID
	}
	upgradeDetails := details.NewDetails(release.VersionWithSnapshot(), details.StateRequested, actionId)
	err = markUpgrade(log, paths.DataFrom(topDir), now, curAgentInstall, prevAgentInstall, action, upgradeDetails, nil)
	if err != nil {
		return "", "", fmt.Errorf("creating upgrade marker: %w", err)
	}

	// return watcher executable and versionedHome to rollback to
	watcherExecutable := watcherHelper.SelectWatcherExecutable(topDir, prevAgentInstall, curAgentInstall)
	return watcherExecutable, targetInstall, nil
}

func rollbackUsingUpgradeMarker(ctx context.Context, log *logger.Logger, watcherHelper WatcherHelper, topDir string, now time.Time, version string, _ *fleetapi.ActionUpgrade) (string, string, error) {
	// read the upgrade marker
	updateMarker, err := LoadMarker(paths.DataFrom(topDir))
	if err != nil {
		return "", "", fmt.Errorf("loading marker: %w", err)
	}

	if updateMarker == nil {
		return "", "", ErrNilUpdateMarker
	}

	// extract the agent installs involved in the upgrade and select the most appropriate watcher executable
	previous, current, err := extractAgentInstallsFromMarker(updateMarker)
	if err != nil {
		return "", "", fmt.Errorf("extracting current and previous install details: %w", err)
	}
	watcherExecutable := watcherHelper.SelectWatcherExecutable(topDir, previous, current)

	var selectedRollbackVersionedHome string

	err = withTakeOverWatcher(ctx, log, topDir, watcherHelper, func() error {
		// read the upgrade marker
		updateMarker, err = LoadMarker(paths.DataFrom(topDir))
		if err != nil {
			return fmt.Errorf("loading marker: %w", err)
		}

		if updateMarker == nil {
			return ErrNilUpdateMarker
		}

		if len(updateMarker.RollbacksAvailable) == 0 {
			return ErrNoRollbacksAvailable
		}

		for versionedHome, rollback := range updateMarker.RollbacksAvailable {
			if rollback.Version == version && now.Before(rollback.ValidUntil) {
				selectedRollbackVersionedHome = versionedHome
				break
			}
		}
		if selectedRollbackVersionedHome == "" {
			return fmt.Errorf("version %q not listed among the available rollbacks: %w", version, ErrNoRollbacksAvailable)
		}
		return nil
	})

	if err != nil {
		// Invoke watcher again (now that we released the watcher applocks)
		_, invokeWatcherErr := watcherHelper.InvokeWatcher(log, watcherExecutable)
		if invokeWatcherErr != nil {
			return "", "", errors.Join(err, fmt.Errorf("invoking watcher: %w", invokeWatcherErr))
		}
		return "", "", err
	}

	return watcherExecutable, selectedRollbackVersionedHome, nil
}

func withTakeOverWatcher(ctx context.Context, log *logger.Logger, topDir string, watcherHelper WatcherHelper, f func() error) error {
	watcherApplock, err := watcherHelper.TakeOverWatcher(ctx, log, topDir)
	if err != nil {
		return fmt.Errorf("taking over watcher processes: %w", err)
	}
	defer func(watcherApplock *filelock.AppLocker) {
		releaseWatcherAppLockerErr := watcherApplock.Unlock()
		if releaseWatcherAppLockerErr != nil {
			log.Warnw("error releasing watcher applock", "error", releaseWatcherAppLockerErr)
		}
	}(watcherApplock)

	return f()
}

func extractAgentInstallsFromMarker(updateMarker *UpdateMarker) (previous agentInstall, current agentInstall, err error) {
	previousParsedVersion, err := version.ParseVersion(updateMarker.PrevVersion)
	if err != nil {
		return previous, current, fmt.Errorf("parsing previous version %q: %w", updateMarker.PrevVersion, err)
	}
	previous = agentInstall{
		parsedVersion: previousParsedVersion,
		version:       updateMarker.PrevVersion,
		hash:          updateMarker.PrevHash,
		versionedHome: updateMarker.PrevVersionedHome,
	}

	currentParsedVersion, err := version.ParseVersion(updateMarker.Version)
	if err != nil {
		return previous, current, fmt.Errorf("parsing current version %q: %w", updateMarker.Version, err)
	}
	current = agentInstall{
		parsedVersion: currentParsedVersion,
		version:       updateMarker.Version,
		hash:          updateMarker.Hash,
		versionedHome: updateMarker.VersionedHome,
	}

	return previous, current, nil
}

func getAvailableRollbacks(rollbackWindow time.Duration, now time.Time, currentVersion string, parsedCurrentVersion *version.ParsedSemVer, currentVersionedHome string, currentHash string) map[string]ttl.TTLMarker {
	if rollbackWindow == disableRollbackWindow {
		// if there's no rollback window it means that no rollback should survive the watcher cleanup at the end of the grace period.
		return nil
	}

	if parsedCurrentVersion == nil || parsedCurrentVersion.Less(*Version_9_3_0_SNAPSHOT) {
		// the version we are upgrading to does not support manual rollbacks
		return nil
	}

	// when multiple rollbacks will be supported, read the existing descriptor
	// at this stage we can get by with a single rollback
	res := make(map[string]ttl.TTLMarker, 1)
	res[currentVersionedHome] = ttl.TTLMarker{
		Version:    currentVersion,
		Hash:       currentHash,
		ValidUntil: now.Add(rollbackWindow),
	}

	return res
}
