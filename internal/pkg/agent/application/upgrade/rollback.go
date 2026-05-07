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

	// data directory path
	dataDirPath := paths.DataFrom(topDirPath)

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

	dirPrefix := fmt.Sprintf("%s-", AgentName)

	log.Infof("versioned homes to keep: %v", versionedHomesToKeep)

	// Build the candidate keep list: what the caller asked for plus the live
	// versioned home (the directory the top-level agent symlink resolves to).
	//
	// Always preserving the live install closes the data-loss hazard described
	// in https://github.com/elastic/elastic-agent/issues/13505: if a caller's
	// keep list is built from a stale marker.VersionedHome that no longer
	// exists on disk, cleanup would otherwise treat the live install as
	// "not in keep" and delete it. The TTL-based rollback retention
	// (marker.RollbacksAvailable) covers the homes operators explicitly want
	// to keep across an upgrade; this guard is the structural backstop on top
	// of that — the symlink is the single source of truth for "the binary the
	// daemon will launch on next start," and that directory must always
	// survive cleanup.
	candidates := append(make([]string, 0, len(versionedHomesToKeep)+1), versionedHomesToKeep...)
	if liveHome, err := liveVersionedHome(topDirPath); err == nil {
		candidates = append(candidates, liveHome)
	} else {
		log.Infow("could not derive live versioned home; cleanup proceeds without protection",
			"error.message", err.Error())
	}

	// Normalize each candidate to a dataDir-relative basename, deduplicate,
	// and drop entries that don't exist on disk so the "Keeping" log line
	// below reflects what is actually being preserved rather than a phantom
	// path. A stale entry is harmless to leave in (the cleanup loop only
	// iterates real subdirs) but misleading on triage; each dropped entry is
	// surfaced as an Info so the cause — usually a stale
	// marker.VersionedHome — is visible in logs.
	var cumulativeError error
	relativeHomePaths := make([]string, 0, len(candidates))
	for _, h := range candidates {
		rel, err := filepath.Rel(dataDirPath, filepath.Join(topDirPath, h))
		if err != nil {
			// We can't normalize this entry, and the cleanup loop below
			// matches dataDir-relative basenames, so an un-normalized path
			// would never match anyway. Record the failure for the caller
			// and skip the entry rather than carry a value forward that
			// can't preserve the directory.
			cumulativeError = goerrors.Join(cumulativeError, fmt.Errorf("extracting elastic-agent path relative to data directory from %s: %w", h, err))
			continue
		}
		if _, statErr := os.Stat(filepath.Join(dataDirPath, rel)); statErr != nil {
			log.Infow("dropping non-existent keep-list entry from cleanup",
				"path", rel, "error.message", statErr.Error())
			continue
		}
		relativeHomePaths = append(relativeHomePaths, rel)
	}

	log.Infof("Starting cleanup of versioned homes. Keeping: %v", relativeHomePaths)

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

// liveVersionedHome resolves the versioned home that the top-level agent
// symlink points at, returned as a path relative to topDirPath. Used by
// cleanup as a defense against stale keep lists deleting the live install
// (https://github.com/elastic/elastic-agent/issues/13505).
//
// Returns the empty string and a non-nil error if the symlink can't be read
// or doesn't resolve to a path under topDirPath.
func liveVersionedHome(topDirPath string) (string, error) {
	symlinkPath := filepath.Join(topDirPath, AgentName)
	if runtime.GOOS == "windows" {
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
