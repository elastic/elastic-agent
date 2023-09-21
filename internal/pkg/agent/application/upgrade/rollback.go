// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package upgrade

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/elastic/elastic-agent/pkg/control"
	"github.com/elastic/elastic-agent/pkg/control/v2/client"

	"github.com/hashicorp/go-multierror"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/internal/pkg/agent/install"
	"github.com/elastic/elastic-agent/internal/pkg/core/backoff"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

const (
	watcherSubcommand  = "watch"
	maxRestartCount    = 5
	restartBackoffInit = 5 * time.Second
	restartBackoffMax  = 90 * time.Second
)

// Rollback rollbacks to previous version which was functioning before upgrade.
func Rollback(ctx context.Context, log *logger.Logger, prevHash string, currentHash string) error {
	// change symlink
	if err := ChangeSymlink(ctx, log, prevHash); err != nil {
		return err
	}

	// revert active commit
	if err := UpdateActiveCommit(log, prevHash); err != nil {
		return err
	}

	// Restart
	log.Info("Restarting the agent after rollback")
	if err := restartAgent(ctx, log); err != nil {
		return err
	}

	// cleanup everything except version we're rolling back into
	return Cleanup(log, prevHash, true, true)
}

// Cleanup removes all artifacts and files related to a specified version.
func Cleanup(log *logger.Logger, currentHash string, removeMarker bool, keepLogs bool) error {
	log.Infow("Cleaning up upgrade", "hash", currentHash, "remove_marker", removeMarker)
	<-time.After(afterRestartDelay)

	// remove upgrade marker
	if removeMarker {
		if err := CleanMarker(log); err != nil {
			return err
		}
	}

	// remove data/elastic-agent-{hash}
	dataDir, err := os.Open(paths.Data())
	if err != nil {
		return err
	}

	subdirs, err := dataDir.Readdirnames(0)
	if err != nil {
		return err
	}

	// remove symlink to avoid upgrade failures, ignore error
	prevSymlink := prevSymlinkPath()
	log.Infow("Removing previous symlink path", "file.path", prevSymlinkPath())
	_ = os.Remove(prevSymlink)

	dirPrefix := fmt.Sprintf("%s-", agentName)
	currentDir := fmt.Sprintf("%s-%s", agentName, currentHash)
	for _, dir := range subdirs {
		if dir == currentDir {
			continue
		}

		if !strings.HasPrefix(dir, dirPrefix) {
			continue
		}

		hashedDir := filepath.Join(paths.Data(), dir)
		log.Infow("Removing hashed data directory", "file.path", hashedDir)
		var ignoredDirs []string
		if keepLogs {
			ignoredDirs = append(ignoredDirs, "logs")
		}
		if cleanupErr := install.RemoveBut(hashedDir, true, ignoredDirs...); cleanupErr != nil {
			err = multierror.Append(err, cleanupErr)
		}
	}

	return err
}

// InvokeWatcher invokes an agent instance using watcher argument for watching behavior of
// agent during upgrade period.
func InvokeWatcher(log *logger.Logger) error {
	if !IsUpgradeable() {
		log.Info("agent is not upgradable, not starting watcher")
		return nil
	}

	cmd := invokeCmd()
	defer func() {
		if cmd.Process != nil {
			log.Infof("releasing watcher %v", cmd.Process.Pid)
			_ = cmd.Process.Release()
		}
	}()

	log.Infow("Starting upgrade watcher", "path", cmd.Path, "args", cmd.Args, "env", cmd.Env, "dir", cmd.Dir)
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start Upgrade Watcher: %w", err)
	}

	upgradeWatcherPID := cmd.Process.Pid
	agentPID := os.Getpid()
	log.Infow("Upgrade Watcher invoked", "agent.upgrade.watcher.process.pid", upgradeWatcherPID, "agent.process.pid", agentPID)

	return nil
}

func restartAgent(ctx context.Context, log *logger.Logger) error {
	restartViaDaemonFn := func(ctx context.Context) error {
		c := client.New()
		err := c.Connect(ctx)
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

	for restartAttempt := 1; restartAttempt <= maxRestartCount; restartAttempt++ {
		backExp.Wait()
		log.Infof("Restarting Agent via control protocol; attempt %d of %d", restartAttempt, maxRestartCount)
		// First, try to restart Agent by sending a restart command
		// to its daemon (via GRPC).
		err := restartViaDaemonFn(ctx)
		if err == nil {
			break
		}
		log.Warnf("Failed to restart agent via control protocol: %s", err.Error())

		// Next, try to restart Agent via the service.
		log.Infof("Restarting Agent via service; attempt %d of %d", restartAttempt, maxRestartCount)
		err = restartViaServiceFn(ctx)
		if err == nil {
			break
		}

		if restartAttempt == maxRestartCount {
			log.Error("Failed to restart agent after final attempt")
			return err
		}

		log.Warnf("Failed to restart agent via service: %s; will try again in %v", err.Error(), backExp.NextWait())
	}

	close(signal)
	return nil
}
