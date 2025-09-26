// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package upgrade

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/filelock"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/reexec"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi"
	"github.com/elastic/elastic-agent/pkg/core/logger"
	"github.com/elastic/elastic-agent/pkg/version"
)

func (u *Upgrader) rollbackToPreviousVersion(ctx context.Context, topDir string, now time.Time, version string, action *fleetapi.ActionUpgrade) (reexec.ShutdownCallbackFn, error) {
	if version == "" {
		return nil, ErrEmptyRollbackVersion
	}

	// check that the upgrade marker exists and is accessible
	updateMarkerPath := markerFilePath(paths.DataFrom(topDir))
	_, err := os.Stat(updateMarkerPath)
	if err != nil {
		return nil, fmt.Errorf("stat() on upgrade marker %q failed: %w", updateMarkerPath, err)
	}

	// read the upgrade marker
	updateMarker, err := LoadMarker(paths.DataFrom(topDir))
	if err != nil {
		return nil, fmt.Errorf("loading marker: %w", err)
	}

	if updateMarker == nil {
		return nil, ErrNilUpdateMarker
	}

	// extract the agent installs involved in the upgrade and select the most appropriate watcher executable
	previous, current, err := extractAgentInstallsFromMarker(updateMarker)
	if err != nil {
		return nil, fmt.Errorf("extracting current and previous install details: %w", err)
	}
	watcherExecutable := u.watcherHelper.SelectWatcherExecutable(topDir, previous, current)

	err = withTakeOverWatcher(ctx, u.log, topDir, u.watcherHelper, func() error {
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
		var selectedRollback *TTLMarker
		for _, rollback := range updateMarker.RollbacksAvailable {
			if rollback.Version == version && now.Before(rollback.ValidUntil) {
				selectedRollback = &rollback
				break
			}
		}
		if selectedRollback == nil {
			return fmt.Errorf("version %q not listed among the available rollbacks: %w", version, ErrNoRollbacksAvailable)
		}

		// rollback
		_, err = u.watcherHelper.InvokeWatcher(u.log, watcherExecutable, "watch", "--rollback", updateMarker.PrevVersionedHome)
		if err != nil {
			return fmt.Errorf("starting rollback command: %w", err)
		}
		u.log.Debug("rollback command started successfully, PID")
		return nil
	})

	if err != nil {
		// Invoke watcher again (now that we released the watcher applocks)
		_, invokeWatcherErr := u.watcherHelper.InvokeWatcher(u.log, watcherExecutable)
		if invokeWatcherErr != nil {
			return nil, errors.Join(err, fmt.Errorf("invoking watcher: %w", invokeWatcherErr))
		}
		return nil, err
	}

	return nil, nil

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

func getAvailableRollbacks(rollbackWindow time.Duration, now time.Time, currentVersion string, parsedCurrentVersion *version.ParsedSemVer, currentVersionedHome string) map[string]TTLMarker {
	if rollbackWindow == 0 {
		// if there's no rollback window it means that no rollback should survive the watcher cleanup at the end of the grace period.
		return nil
	}

	if parsedCurrentVersion == nil || parsedCurrentVersion.Less(*Version_9_3_0_SNAPSHOT) {
		// the version we are upgrading to does not support manual rollbacks
		return nil
	}

	// when multiple rollbacks will be supported, read the existing descriptor
	// at this stage we can get by with a single rollback
	res := make(map[string]TTLMarker, 1)
	res[currentVersionedHome] = TTLMarker{
		Version:    currentVersion,
		ValidUntil: now.Add(rollbackWindow),
	}

	return res
}
