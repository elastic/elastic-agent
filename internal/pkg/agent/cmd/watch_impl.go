// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package cmd

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade"
	"github.com/elastic/elastic-agent/pkg/control/v2/client"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

type upgradeAgentWatcher struct{}

func (a upgradeAgentWatcher) Watch(ctx context.Context, tilGrace, errorCheckInterval time.Duration, log *logp.Logger) error {
	return watch(ctx, tilGrace, errorCheckInterval, log)
}

type upgradeInstallationModifier struct{}

func (a upgradeInstallationModifier) Cleanup(log *logger.Logger, topDirPath string, removeMarker, keepLogs bool, versionedHomesToKeep ...string) error {
	return upgrade.Cleanup(log, topDirPath, removeMarker, keepLogs, versionedHomesToKeep...)
}

func (a upgradeInstallationModifier) Rollback(ctx context.Context, log *logger.Logger, c client.Client, topDirPath, prevVersionedHome, prevHash string, opts ...upgrade.RollbackOption) error {
	var actualOpts []upgrade.RollbackOpt

	for _, o := range opts {
		actualOpts = append(actualOpts, func(rs *upgrade.RollbackSettings) { o(rs) })
	}

	return upgrade.RollbackWithOpts(ctx, log, c, topDirPath, prevVersionedHome, prevHash, actualOpts...)
}

func watch(ctx context.Context, tilGrace time.Duration, errorCheckInterval time.Duration, log *logger.Logger) error {
	errChan := make(chan error)

	ctx, cancel := context.WithCancel(ctx)

	//cleanup
	defer func() {
		cancel()
		close(errChan)
	}()

	agtWatcher := upgrade.NewAgentWatcher(errChan, log, errorCheckInterval)
	go agtWatcher.Run(ctx)

	// Allow for signals to interrupt the watch
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT, syscall.SIGHUP)
	defer signal.Stop(signals)

	graceTimer := time.NewTimer(tilGrace)
	defer graceTimer.Stop()

	return watchLoop(ctx, log, signals, errChan, graceTimer.C)
}

func watchLoop(ctx context.Context, log *logger.Logger, signals <-chan os.Signal, errChan <-chan error, graceTimer <-chan time.Time) error {
	for {
		select {
		case s := <-signals:
			log.Infof("received signal: (%d): %v during watch", s, s)
			if s == syscall.SIGINT || s == syscall.SIGTERM {
				log.Infof("received signal: (%d): %v. Exiting watch", s, s)
				return ErrWatchCancelled
			}
			continue
		case <-ctx.Done():
			return nil
		// grace period passed, agent is considered stable
		case <-graceTimer:
			log.Info("Grace period passed, not watching")
			return nil
		// Agent in degraded state.
		case err := <-errChan:
			log.Errorf("Agent Error detected: %s", err.Error())
			return err
		}
	}
}
