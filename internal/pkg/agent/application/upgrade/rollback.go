// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package upgrade

import (
	"context"
	goerrors "errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"

	"google.golang.org/grpc"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/internal/pkg/agent/install"
	"github.com/elastic/elastic-agent/pkg/backoff"
	"github.com/elastic/elastic-agent/pkg/control"
	"github.com/elastic/elastic-agent/pkg/control/v2/client"
	"github.com/elastic/elastic-agent/pkg/core/logger"
	"github.com/elastic/elastic-agent/pkg/utils"
)

const (
	watcherSubcommand  = "watch"
	maxRestartCount    = 5
	restartBackoffInit = 5 * time.Second
	restartBackoffMax  = 90 * time.Second
)

// Rollback rollbacks to previous version which was functioning before upgrade.
func Rollback(ctx context.Context, log *logger.Logger, c client.Client, topDirPath, prevVersionedHome, prevHash string) error {
	symlinkPath := filepath.Join(topDirPath, agentName)

	var symlinkTarget string
	if prevVersionedHome != "" {
		symlinkTarget = paths.BinaryPath(filepath.Join(topDirPath, prevVersionedHome), agentName)
	} else {
		// fallback for upgrades that didn't use the manifest and path remapping
		hashedDir := fmt.Sprintf("%s-%s", agentName, prevHash)
		// paths.BinaryPath properly derives the binary directory depending on the platform. The path to the binary for macOS is inside of the app bundle.
		symlinkTarget = paths.BinaryPath(filepath.Join(paths.DataFrom(topDirPath), hashedDir), agentName)
	}
	// change symlink
	if err := changeSymlink(log, topDirPath, symlinkPath, symlinkTarget); err != nil {
		return err
	}

	// revert active commit
	if err := UpdateActiveCommit(log, topDirPath, prevHash, os.WriteFile); err != nil {
		return err
	}

	// Restart
	log.Info("Restarting the agent after rollback")
	if err := restartAgent(ctx, log, c); err != nil {
		return err
	}

	// cleanup everything except version we're rolling back into
	return Cleanup(log, topDirPath, prevVersionedHome, prevHash, true, true)
}

// Cleanup removes all artifacts and files related to a specified version.
func Cleanup(log *logger.Logger, topDirPath, currentVersionedHome, currentHash string, removeMarker, keepLogs bool) error {
	return cleanup(log, topDirPath, currentVersionedHome, currentHash, removeMarker, keepLogs, afterRestartDelay)
}

func cleanup(log *logger.Logger, topDirPath, currentVersionedHome, currentHash string, removeMarker, keepLogs bool, delay time.Duration) error {
	log.Infow("Cleaning up upgrade", "hash", currentHash, "remove_marker", removeMarker)
	<-time.After(delay)

	// data directory path
	dataDirPath := paths.DataFrom(topDirPath)

	// The live versioned home is identified from the top-level agent symlink
	// — the canonical record of what the daemon launches. If that symlink is
	// unreadable for any reason, cleanup refuses to proceed: deciding what to
	// keep without an authoritative live-install reference would risk
	// deleting the live install, and the loud abort produces a recurring
	// Error signal that an operator can investigate before the next restart
	// fails. See
	// https://github.com/elastic/elastic-agent/issues/13505 for the data-loss
	// hazard this guard closes.
	liveHome, err := liveVersionedHome(topDirPath)
	if err != nil {
		return fmt.Errorf("cannot identify live versioned home from symlink, refusing to proceed with cleanup: %w", err)
	}

	// remove upgrade marker
	if removeMarker {
		if err := CleanMarker(log, dataDirPath); err != nil {
			return err
		}
	}

	// remove data/elastic-agent-{hash}
	dataDir, err := os.Open(dataDirPath)
	if err != nil {
		return err
	}
	defer func(dataDir *os.File) {
		err := dataDir.Close()
		if err != nil {
			log.Errorw("Error closing data directory", "file.directory", dataDirPath)
		}
	}(dataDir)

	subdirs, err := dataDir.Readdirnames(0)
	if err != nil {
		return err
	}

	// remove symlink to avoid upgrade failures, ignore error
	prevSymlink := prevSymlinkPath(topDirPath)
	log.Infow("Removing previous symlink path", "file.path", prevSymlinkPath(topDirPath))
	_ = os.Remove(prevSymlink)

	dirPrefix := fmt.Sprintf("%s-", agentName)

	// Compute the caller's keep path and the live install path, both
	// normalized to dataDir-relative basenames. Drop phantom entries (paths
	// that no longer exist on disk) with an Info log so stale
	// marker.VersionedHome values are visible in triage output.
	var callerKeep string
	if currentVersionedHome != "" {
		var callerRelErr error
		callerKeep, callerRelErr = filepath.Rel("data", currentVersionedHome)
		if callerRelErr != nil {
			return fmt.Errorf("extracting elastic-agent path relative to data directory from %s: %w", currentVersionedHome, callerRelErr)
		}
	} else {
		callerKeep = fmt.Sprintf("%s-%s", agentName, currentHash)
	}
	liveKeep, liveRelErr := filepath.Rel(dataDirPath, filepath.Join(topDirPath, liveHome))
	if liveRelErr != nil {
		return fmt.Errorf("extracting live versioned home relative to data directory: %w", liveRelErr)
	}
	seen := make(map[string]bool)
	relativeHomePaths := make([]string, 0, 2)
	for _, rel := range []string{callerKeep, liveKeep} {
		if seen[rel] {
			continue
		}
		seen[rel] = true
		if _, statErr := os.Stat(filepath.Join(dataDirPath, rel)); statErr != nil {
			log.Infow("dropping non-existent keep-list entry from cleanup",
				"path", rel, "error.message", statErr.Error())
			continue
		}
		relativeHomePaths = append(relativeHomePaths, rel)
	}
	log.Infof("Starting cleanup of versioned homes. Keeping: %v", relativeHomePaths)

	var errs []error
	for _, dir := range subdirs {
		if slices.Contains(relativeHomePaths, dir) {
			continue
		}

		if !strings.HasPrefix(dir, dirPrefix) {
			continue
		}

		hashedDir := filepath.Join(dataDirPath, dir)
		log.Infow("Removing hashed data directory", "file.path", hashedDir)
		var ignoredDirs []string
		if keepLogs {
			ignoredDirs = append(ignoredDirs, "logs")
		}
		if cleanupErr := install.RemoveBut(log, hashedDir, true, ignoredDirs...); cleanupErr != nil {
			errs = append(errs, cleanupErr)
		}
	}

	return goerrors.Join(errs...)
}

// InvokeWatcher invokes an agent instance using watcher argument for watching behavior of
// agent during upgrade period.
func InvokeWatcher(log *logger.Logger, agentExecutable string) (*exec.Cmd, error) {
	if !IsUpgradeable() {
		log.Info("agent is not upgradable, not starting watcher")
		return nil, nil
	}

	cmd := invokeCmd(agentExecutable)
	log.Infow("Starting upgrade watcher", "path", cmd.Path, "args", cmd.Args, "env", cmd.Env, "dir", cmd.Dir)
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start Upgrade Watcher: %w", err)
	}

	upgradeWatcherPID := cmd.Process.Pid
	agentPID := os.Getpid()

	go func() {
		if err := cmd.Wait(); err != nil {
			log.Infow("Upgrade Watcher exited with error", "agent.upgrade.watcher.process.pid", "agent.process.pid", agentPID, upgradeWatcherPID, "error.message", err)
		}
	}()

	log.Infow("Upgrade Watcher invoked", "agent.upgrade.watcher.process.pid", upgradeWatcherPID, "agent.process.pid", agentPID)

	return cmd, nil

}

func restartAgent(ctx context.Context, log *logger.Logger, c client.Client) error {
	restartViaDaemonFn := func(ctx context.Context) error {
		connectCtx, connectCancel := context.WithTimeout(ctx, 3*time.Second)
		defer connectCancel()
		//nolint:staticcheck // requires changing client signature
		err := c.Connect(connectCtx, grpc.WithBlock(), grpc.WithDisableRetry())
		if err != nil {
			return errors.New(err, "failed communicating to running daemon", errors.TypeNetwork, errors.M("socket", control.Address()))
		}
		defer c.Disconnect()

		err = c.Restart(ctx)
		if err != nil {
			return errors.New(err, "failed trigger restart of daemon")
		}

		return nil
	}

	restartViaServiceFn := func(ctx context.Context) error {
		topPath := paths.Top()
		err := install.RestartService(topPath)
		if err != nil {
			return fmt.Errorf("failed to restart agent via service: %w", err)
		}

		return nil
	}

	signal := make(chan struct{})
	backExp := backoff.NewExpBackoff(signal, restartBackoffInit, restartBackoffMax)
	root, _ := utils.HasRoot() // error ignored

	for restartAttempt := 1; restartAttempt <= maxRestartCount; restartAttempt++ {
		// only use exp backoff when retrying
		if restartAttempt != 1 {
			backExp.Wait()
		}
		log.Infof("Restarting Agent via control protocol; attempt %d of %d", restartAttempt, maxRestartCount)
		// First, try to restart Agent by sending a restart command
		// to its daemon (via GRPC).
		err := restartViaDaemonFn(ctx)
		if err == nil {
			break
		}
		log.Warnf("Failed to restart agent via control protocol: %s", err.Error())

		// Next, try to restart Agent via the service. (only if root)
		if root {
			log.Infof("Restarting Agent via service; attempt %d of %d", restartAttempt, maxRestartCount)
			err = restartViaServiceFn(ctx)
			if err == nil {
				break
			}
			log.Warnf("Failed to restart agent via service: %s", err.Error())
		}

		if restartAttempt == maxRestartCount {
			log.Error("Failed to restart agent after final attempt")
			return err
		}
		log.Warnf("Failed to restart agent; will try again in %v", backExp.NextWait())
	}

	close(signal)
	return nil
}

// liveVersionedHome resolves the versioned home that the top-level agent
// symlink points at, returned as a path relative to topDirPath. Used by
// cleanup as a defense against stale keep lists deleting the live install
// (https://github.com/elastic/elastic-agent/issues/13505).
//
// Returns the empty string and a non-nil error if the symlink can't be read
// or doesn't resolve to a path under topDirPath.
func liveVersionedHome(topDirPath string) (string, error) {
	symlinkPath := filepath.Join(topDirPath, agentName)
	if runtime.GOOS == windows {
		symlinkPath += exe
	}
	target, err := os.Readlink(symlinkPath)
	if err != nil {
		return "", fmt.Errorf("reading symlink %q: %w", symlinkPath, err)
	}
	// Resolve a relative symlink target against the symlink's directory.
	if !filepath.IsAbs(target) {
		target = filepath.Join(filepath.Dir(symlinkPath), target)
	}
	// target is the binary path; strip down to the versioned home.
	// On macOS, paths.BinaryPath produces an extra three nested directories
	// (<versionedHome>/elastic-agent.app/Contents/MacOS/elastic-agent), so
	// we strip those levels to recover the versioned home.
	home := filepath.Dir(target)
	if runtime.GOOS == "darwin" {
		home = filepath.Dir(filepath.Dir(filepath.Dir(home)))
	}
	// os.Readlink returns the literal target even if it dangles, so an
	// existence check here is what proves the symlink still identifies a
	// real install.
	if _, err := os.Stat(home); err != nil {
		return "", fmt.Errorf("stat versioned home %q: %w", home, err)
	}
	rel, err := filepath.Rel(topDirPath, home)
	if err != nil {
		return "", fmt.Errorf("computing %q relative to %q: %w", home, topDirPath, err)
	}
	// filepath.Rel is purely lexical and happily returns "../foo" when home
	// is outside topDirPath. Enforce the documented contract here so callers
	// (cleanup's keep list) never get a path that traverses out of the data
	// dir, which could let a malicious or corrupt symlink redirect cleanup
	// decisions.
	if !filepath.IsLocal(rel) {
		return "", fmt.Errorf("symlink target %q resolves outside top directory %q", home, topDirPath)
	}
	return rel, nil
}
