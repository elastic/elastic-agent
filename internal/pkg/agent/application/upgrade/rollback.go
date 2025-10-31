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
	"slices"
	"strings"
	"time"

	"google.golang.org/grpc"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/internal/pkg/agent/install"
	"github.com/elastic/elastic-agent/internal/pkg/core/backoff"
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

	// cleanup everything except version we're rolling back into
	return Cleanup(log, topDirPath, settings.RemoveMarker, true, prevVersionedHome)
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

	relativeHomePaths := make([]string, len(versionedHomesToKeep))
	for i, h := range versionedHomesToKeep {
		relHomePath, err := filepath.Rel("data", h)
		if err != nil {
			return fmt.Errorf("extracting elastic-agent path relative to data directory from %s: %w", h, err)
		}
		relativeHomePaths[i] = relHomePath
	}

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
		if cleanupErr := install.RemoveBut(hashedDir, true, ignoredDirs...); cleanupErr != nil {
			errs = append(errs, cleanupErr)
		}
	}

	return goerrors.Join(errs...)
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
