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
	"strings"
	"time"

	"google.golang.org/grpc"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/ttl"
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
	return RollbackWithOpts(ctx, log, c, topDirPath, prevVersionedHome, prevHash)
}

var FatalRollbackError = errors.New("fatal rollback error")

type RollbackSettings struct {
	SkipCleanup    bool
	SkipRestart    bool
	PreRestartHook RollbackHook
	RemoveMarker   bool
}

func NewRollbackSettings(opts ...RollbackOpt) *RollbackSettings {
	rs := new(RollbackSettings)
	for _, opt := range opts {
		opt(rs)
	}
	return rs
}

type RollbackOpt func(*RollbackSettings)

func (r *RollbackSettings) SetSkipCleanup(skipCleanup bool) {
	r.SkipCleanup = skipCleanup
}

func (r *RollbackSettings) SetSkipRestart(skipRestart bool) {
	r.SkipRestart = skipRestart
}

func (r *RollbackSettings) SetPreRestartHook(preRestartHook RollbackHook) {
	r.PreRestartHook = preRestartHook
}

func (r *RollbackSettings) SetRemoveMarker(removeMarker bool) {
	r.RemoveMarker = removeMarker
}

func RollbackWithOpts(ctx context.Context, log *logger.Logger, c client.Client, topDirPath string, prevVersionedHome string, prevHash string, opts ...RollbackOpt) error {

	settings := NewRollbackSettings(opts...)

	symlinkPath := filepath.Join(topDirPath, AgentName)

	if prevVersionedHome == "" {
		// fallback for upgrades that didn't use the manifest and path remapping
		hashedDir := fmt.Sprintf("%s-%s", AgentName, prevHash)
		prevVersionedHome = filepath.Join("data", hashedDir)
	}

	// paths.BinaryPath properly derives the binary directory depending on the platform. The path to the binary for macOS is inside of the app bundle.
	symlinkTarget := paths.BinaryPath(filepath.Join(topDirPath, prevVersionedHome), AgentName)

	// change symlink
	if err := changeSymlink(log, topDirPath, symlinkPath, symlinkTarget); err != nil {
		return err
	}

	// revert active commit
	if err := UpdateActiveCommit(log, topDirPath, prevHash, os.WriteFile); err != nil {
		return err
	}

	// Hook
	if settings.PreRestartHook != nil {
		hookErr := settings.PreRestartHook(ctx, log, topDirPath)
		if hookErr != nil {
			if errors.Is(hookErr, FatalRollbackError) {
				return fmt.Errorf("pre-restart hook failed: %w", hookErr)
			}

			log.Warnf("pre-restart hook failed: %v", hookErr)
		}
	}

	if settings.SkipRestart {
		log.Info("Skipping restart")
		return nil
	}

	// Restart
	log.Info("Restarting the agent after rollback")
	if err := restartAgent(ctx, log, c); err != nil {
		return err
	}

	if settings.SkipCleanup {
		log.Info("Skipping cleanup")
		return nil
	}

	// cleanup everything except the version we're rolling back into and any
	// in-TTL rollback targets recorded in the live TTL registry. The registry
	// read is best-effort: if it fails we fall back to preserving only
	// prevVersionedHome rather than aborting the rollback.
	versionedHomesToKeep := []string{prevVersionedHome}
	inTTL, err := InTTLRollbacks(log, topDirPath, time.Now())
	if err != nil {
		log.Infow("could not read TTL registry; cleanup will only preserve the rollback target",
			"error.message", err.Error())
	} else {
		versionedHomesToKeep = append(versionedHomesToKeep, inTTL...)
	}
	return Cleanup(log, topDirPath, settings.RemoveMarker, true, versionedHomesToKeep...)
}

// Cleanup removes all artifacts and files related to a specified version.
func Cleanup(log *logger.Logger, topDirPath string, removeMarker, keepLogs bool, versionedHomesToKeep ...string) error {
	return cleanup(log, topDirPath, removeMarker, keepLogs, afterRestartDelay, versionedHomesToKeep...)
}

func cleanup(log *logger.Logger, topDirPath string, removeMarker, keepLogs bool, delay time.Duration, versionedHomesToKeep ...string) error {
	log.Infow("Cleaning up upgrade", "remove_marker", removeMarker)
	<-time.After(delay)

	dataDirPath := paths.DataFrom(topDirPath)

	// Snapshot the directory listing before reading any markers so that directories
	// created after this point cannot be swept this run.
	allAgentDirs, err := snapshotAgentDirs(topDirPath)
	if err != nil {
		return err
	}

	// Read TTL rollbacks fresh after the snapshot.
	if inTTL, ttlErr := InTTLRollbacks(log, topDirPath, time.Now()); ttlErr != nil {
		log.Infow("could not re-read TTL registry during cleanup; continuing with existing keep-list", "error.message", ttlErr.Error())
	} else {
		versionedHomesToKeep = append(versionedHomesToKeep, inTTL...)
	}

	// requireMarkerDetails=true: reject ambiguous legacy markers (nil Details) so they
	// can't silently protect dirs that should be swept. Fatal on marker or symlink error: see #13505.
	keepDirs, keepDirsErr := buildKeepDirs(log, topDirPath, true, versionedHomesToKeep)
	if keepDirsErr != nil {
		return fmt.Errorf("refusing to proceed with cleanup: %w", keepDirsErr)
	}

	// Remove upgrade marker now that its content has been captured above.
	if removeMarker {
		if err := CleanMarker(log, dataDirPath); err != nil {
			return err
		}
	}

	// remove symlink to avoid upgrade failures, ignore error
	prevSymlink := prevSymlinkPath(topDirPath)
	log.Infow("Removing previous symlink path", "file.path", prevSymlinkPath(topDirPath))
	_ = os.Remove(prevSymlink)

	// Partition the snapshot. Track which keepDirs entries matched a real dir so
	// phantom entries (stale marker.VersionedHome etc.) can be logged below.
	var toRemove, keptDirs []string
	for _, absPath := range allAgentDirs {
		relPath, relErr := filepath.Rel(topDirPath, absPath)
		if relErr != nil {
			continue
		}
		relPath = filepath.Clean(relPath)
		if keepDirs[relPath] {
			keptDirs = append(keptDirs, relPath)
			delete(keepDirs, relPath)
		} else {
			toRemove = append(toRemove, relPath)
		}
	}
	for d := range keepDirs {
		log.Infow("dropping non-existent keep-list entry from cleanup", "path", d)
	}

	log.Infof("Starting cleanup of versioned homes. Keeping: %v", keptDirs)

	var cumulativeError error
	for _, relPath := range toRemove {
		hashedDir := filepath.Join(topDirPath, relPath)
		log.Infow("Removing hashed data directory", "file.path", hashedDir)
		var ignoredDirs []string
		if keepLogs {
			ignoredDirs = append(ignoredDirs, "logs")
		}
		if cleanupErr := install.RemoveBut(log, hashedDir, true, ignoredDirs...); cleanupErr != nil {
			cumulativeError = goerrors.Join(cumulativeError, cleanupErr)
		}
	}

	return cumulativeError
}

// InTTLRollbacks reads the live TTL registry under topDir and returns the
// versioned homes whose .ttl is parseable AND not expired (i.e. that
// CleanupExpiredRollbacks would NOT remove). Reusing the cleanup predicate
// keeps the keep-list and the periodic cleanup in lock-step.
//
// Directories whose .ttl is unparseable are deliberately NOT included: under
// the current registry contract a parseable TTL is the only proof an install
// is a valid rollback target, so a malformed entry is treated like a missing
// one — the directory is unprotected and will be swept by Cleanup. This
// preserves the self-healing property that a corrupt .ttl outside the active
// install gets reaped at the next rollback.
//
// GetAll (vs. Get) is used so that one corrupt .ttl file does not prevent the
// other in-TTL entries from being preserved.
func InTTLRollbacks(log *logger.Logger, topDir string, now time.Time) ([]string, error) {
	markers, malformed, err := ttl.NewTTLMarkerRegistry(log, topDir).GetAll()
	if err != nil {
		return nil, fmt.Errorf("getting available rollbacks: %w", err)
	}
	var inTTL []string
	for versionedHome, ttlMarker := range markers {
		if CleanupExpiredRollbacks(log, now, versionedHome, ttlMarker) {
			continue
		}
		log.Debugf("Adding rollback %s:%+v to the directories to keep during cleanup", versionedHome, ttlMarker)
		inTTL = append(inTTL, versionedHome)
	}
	for versionedHome, parseErr := range malformed {
		log.Infow("rollback directory has unparseable TTL marker; not protecting it from cleanup",
			"versionedHome", versionedHome, "error.message", parseErr.Error())
	}
	return inTTL, nil
}

// InvokeWatcher invokes an agent instance using watcher argument for watching behavior of
// agent during upgrade period.
func InvokeWatcher(log *logger.Logger, agentExecutable string, additionalWatchArgs ...string) (*exec.Cmd, error) {
	if !IsUpgradeable() {
		log.Info("agent is not upgradable, not starting watcher")
		return nil, nil
	}
	// invokeWatcherCmd and StartWatcherCmd are platform-specific functions dealing with process launching details.
	cmd, err := StartWatcherCmd(log, func() *exec.Cmd { return invokeWatcherCmd(agentExecutable, additionalWatchArgs...) })
	if err != nil {
		return nil, fmt.Errorf("starting watcher process: %w", err)
	}

	upgradeWatcherPID := cmd.Process.Pid
	agentPID := os.Getpid()
	log.Infow("Upgrade Watcher invoked", "agent.upgrade.watcher.process.pid", upgradeWatcherPID, "agent.process.pid", agentPID)

	return cmd, nil

}

type WatcherInvocationOpt func(opts *watcherInvocationOptions)
type watcherHook func()

type watcherInvocationOptions struct {
	postWatchHook watcherHook
}

func WithWatcherPostWaitHook(h watcherHook) WatcherInvocationOpt {
	return func(opts *watcherInvocationOptions) {
		opts.postWatchHook = h
	}
}

func applyWatcherInvocationOpts(opts ...WatcherInvocationOpt) *watcherInvocationOptions {
	invocationOpts := new(watcherInvocationOptions)
	for _, opt := range opts {
		opt(invocationOpts)
	}
	return invocationOpts
}

type cmdFactory func() *exec.Cmd

func invokeWatcherCmd(agentExecutable string, additionalWatchArgs ...string) *exec.Cmd {
	watchArgs := []string{
		watcherSubcommand,
		"--path.config", paths.Config(),
		"--path.home", paths.Top(),
	}

	watchArgs = append(watchArgs, additionalWatchArgs...)

	return InvokeCmdWithArgs(
		agentExecutable,
		watchArgs...,
	)
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

// snapshotAgentDirs returns absolute paths of all elastic-agent-* dirs in the data directory.
// Take the snapshot before reading markers or TTL entries: directories created by a concurrent
// upgrade afterward won't appear and therefore can't be swept by this cleanup run.
func snapshotAgentDirs(topDir string) ([]string, error) {
	entries, err := os.ReadDir(paths.DataFrom(topDir))
	if err != nil {
		if goerrors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("reading data directory: %w", err)
	}
	var dirs []string
	for _, entry := range entries {
		if entry.IsDir() && strings.HasPrefix(entry.Name(), "elastic-agent-") {
			dirs = append(dirs, filepath.Join(paths.DataFrom(topDir), entry.Name()))
		}
	}
	return dirs, nil
}

// buildKeepDirs returns the set of topDir-relative paths that cleanup must not remove.
// extraDirs are caller-supplied (current running home, unexpired TTL entries, etc.).
// The upgrade marker dirs and symlink target are always added on top.
//
// requireMarkerDetails=true protects marker dirs only when the marker has explicit
// non-terminal state, preventing ambiguous legacy markers from expanding the keep set.
//
// Both the marker error and the symlink error are returned so the caller can decide
// whether to skip removals entirely.
func buildKeepDirs(log *logger.Logger, topDir string, requireMarkerDetails bool, extraDirs []string) (map[string]bool, error) {
	keep := make(map[string]bool, len(extraDirs)+3)
	for _, d := range extraDirs {
		keep[filepath.Clean(d)] = true
	}

	marker, markerErr := LoadMarker(paths.DataFrom(topDir))
	if markerErr != nil {
		// The marker exists but cannot be read or parsed. We cannot determine which
		// directories it references, so we refuse to proceed rather than risk sweeping
		// a directory that an in-progress upgrade depends on.
		log.Warnw("could not read upgrade marker during cleanup; skipping removals to avoid sweeping marker-referenced directories", "error.message", markerErr.Error())
		return keep, markerErr
	} else if marker != nil && !IsTerminalState(marker) && (!requireMarkerDetails || marker.Details != nil) {
		if marker.VersionedHome != "" {
			keep[filepath.Clean(marker.VersionedHome)] = true
		}
		if marker.PrevVersionedHome != "" {
			keep[filepath.Clean(marker.PrevVersionedHome)] = true
		}
	}

	symlinkHome, symlinkErr := liveVersionedHome(topDir)
	if symlinkErr != nil {
		log.Warnw("could not resolve live versioned home symlink during cleanup; skipping removals to avoid sweeping the live install", "error.message", symlinkErr.Error())
		return keep, symlinkErr
	}
	keep[symlinkHome] = true
	return keep, nil
}

// liveVersionedHome resolves the versioned home that the top-level agent
// symlink points at, returned as a path relative to topDirPath. Used by
// cleanup as a defense against stale keep lists deleting the live install
// (https://github.com/elastic/elastic-agent/issues/13505).
//
// Returns the empty string and a non-nil error if the symlink can't be read
// or doesn't resolve to a path under topDirPath.
func liveVersionedHome(topDirPath string) (string, error) {
	symlinkPath := filepath.Join(topDirPath, AgentName)
	if runtime.GOOS == windowsOSName {
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
