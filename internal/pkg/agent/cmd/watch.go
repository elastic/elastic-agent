// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/elastic-agent-libs/logp/configure"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/filelock"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/details"
	"github.com/elastic/elastic-agent/internal/pkg/agent/configuration"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/internal/pkg/cli"
	"github.com/elastic/elastic-agent/internal/pkg/config"
	"github.com/elastic/elastic-agent/internal/pkg/release"
	"github.com/elastic/elastic-agent/pkg/core/logger"
	agtversion "github.com/elastic/elastic-agent/pkg/version"
	"github.com/elastic/elastic-agent/version"
)

const (
	watcherName     = "elastic-agent-watcher"
	watcherLockFile = "watcher.lock"
)

func newWatchCommandWithArgs(_ []string, streams *cli.IOStreams) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "watch",
		Short: "Watch the Elastic Agent for failures and initiate rollback",
		Long:  `This command watches Elastic Agent for failures and initiates rollback if necessary.`,
		Run: func(_ *cobra.Command, _ []string) {
			cfg := getConfig(streams)
			log, err := configuredLogger(cfg)
			if err != nil {
				fmt.Fprintf(streams.Err, "Error configuring logger: %v\n%s\n", err, troubleshootMessage())
				os.Exit(3)
			}

			// Make sure to flush any buffered logs before we're done.
			defer log.Sync() //nolint:errcheck // flushing buffered logs is best effort.

			if err := watchCmd(log, cfg); err != nil {
				log.Errorw("Watch command failed", "error.message", err)
				fmt.Fprintf(streams.Err, "Watch command failed: %v\n%s\n", err, troubleshootMessage())
				os.Exit(4)
			}
		},
	}

	return cmd
}

func watchCmd(log *logp.Logger, cfg *configuration.Configuration) error {
	log.Infow("Upgrade Watcher started", "process.pid", os.Getpid(), "agent.version", version.GetAgentPackageVersion())
	marker, err := upgrade.LoadMarker()
	if err != nil {
		log.Error("failed to load marker", err)
		return err
	}
	if marker == nil {
		// no marker found we're not in upgrade process
		log.Infof("update marker not present at '%s'", paths.Data())
		return nil
	}

	locker := filelock.NewAppLocker(paths.Top(), watcherLockFile)
	if err := locker.TryLock(); err != nil {
		if errors.Is(err, filelock.ErrAppAlreadyRunning) {
			log.Info("exiting, lock already exists")
			return nil
		}

		log.Error("failed to acquire lock", err)
		return err
	}
	defer func() {
		_ = locker.Unlock()
	}()

	isWithinGrace, tilGrace := gracePeriod(marker, cfg.Settings.Upgrade.Watcher.GracePeriod)
	if !isWithinGrace {
		log.Infof("not within grace [updatedOn %v] %v", marker.UpdatedOn.String(), time.Since(marker.UpdatedOn).String())
		// if it is started outside of upgrade loop
		// if we're not within grace and marker is still there it might mean
		// that cleanup was not performed ok, cleanup everything except current version
		// hash is the same as hash of agent which initiated watcher.
		if err := upgrade.Cleanup(log, release.ShortCommit(), true, false); err != nil {
			log.Error("clean up of prior watcher run failed", err)
		}
		// exit nicely
		return nil
	}

	errorCheckInterval := cfg.Settings.Upgrade.Watcher.ErrorCheck.Interval
	ctx := context.Background()
	if err := watch(ctx, tilGrace, errorCheckInterval, log); err != nil {
		log.Error("Error detected, proceeding to rollback: %v", err)

		// If we are upgrading from version >= 8.12.0, marker.Details should be non-nil
		// because the Agent we upgraded FROM would've written upgrade details in the upgrade
		// marker. However, if we're upgrading from version < 8.12.0, the marker won't
		// contain upgrade details, so we populate them now.
		if marker.Details == nil {
			fromVersion, err := agtversion.ParseVersion(marker.PrevVersion)
			if err != nil {
				log.Warnf("upgrade details are nil, but unable to parse version being upgraded from [%s]: %s", marker.PrevVersion, err.Error())
			} else if fromVersion.Less(*agtversion.NewParsedSemVer(8, 12, 0, "", "")) {
				log.Warnf("upgrade details are unexpectedly nil, upgrading from version [%s]", marker.PrevVersion)
			}

			marker.Details = details.NewDetails(version.GetAgentPackageVersion(), details.StateRollback, marker.GetActionID())
		}

		marker.Details.SetState(details.StateRollback)
		err = upgrade.SaveMarker(marker)
		if err != nil {
			log.Errorf("unable to save upgrade marker before attempting to rollback: %s", err.Error())
		}

		err = upgrade.Rollback(ctx, log, marker.PrevHash, marker.Hash)
		if err != nil {
			log.Error("rollback failed", err)

			marker.Details.Fail(err)
			err = upgrade.SaveMarker(marker)
			if err != nil {
				log.Errorf("unable to save upgrade marker after rollback failed: %s", err.Error())
			}
		}
		return err
	}

	// watch succeeded - upgrade was successful!
	marker.Details.SetState(details.StateCompleted)
	err = upgrade.SaveMarker(marker)
	if err != nil {
		log.Errorf("unable to save upgrade marker after successful watch: %s", err.Error())
	}

	// cleanup older versions,
	// in windows it might leave self untouched, this will get cleaned up
	// later at the start, because for windows we leave marker untouched.
	//
	// Why is this being skipped on Windows? The comment above is not clear.
	// issue: https://github.com/elastic/elastic-agent/issues/3027
	removeMarker := !isWindows()
	err = upgrade.Cleanup(log, marker.Hash, removeMarker, false)
	if err != nil {
		log.Error("cleanup after successful watch failed", err)
	}
	return err
}

func isWindows() bool {
	return runtime.GOOS == "windows"
}

func watch(ctx context.Context, tilGrace time.Duration, errorCheckInterval time.Duration, log *logger.Logger) error {
	errChan := make(chan error)

	ctx, cancel := context.WithCancel(ctx)

	//cleanup
	defer func() {
		cancel()
		close(errChan)
	}()

	agentWatcher := upgrade.NewAgentWatcher(errChan, log, errorCheckInterval)
	go agentWatcher.Run(ctx)

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT, syscall.SIGHUP)

	t := time.NewTimer(tilGrace)
	defer t.Stop()

WATCHLOOP:
	for {
		select {
		case <-signals:
			// ignore
			continue
		case <-ctx.Done():
			break WATCHLOOP
		// grace period passed, agent is considered stable
		case <-t.C:
			log.Info("Grace period passed, not watching")
			break WATCHLOOP
		// Agent in degraded state.
		case err := <-errChan:
			log.Errorf("Agent Error detected: %s", err.Error())
			return err
		}
	}

	return nil
}

// gracePeriod returns true if it is within grace period and time until grace period ends.
// otherwise it returns false and 0
func gracePeriod(marker *upgrade.UpdateMarker, gracePeriodDuration time.Duration) (bool, time.Duration) {
	sinceUpdate := time.Since(marker.UpdatedOn)

	if 0 < sinceUpdate && sinceUpdate < gracePeriodDuration {
		return true, gracePeriodDuration - sinceUpdate
	}

	return false, gracePeriodDuration
}

func configuredLogger(cfg *configuration.Configuration) (*logger.Logger, error) {
	cfg.Settings.LoggingConfig.Beat = watcherName
	cfg.Settings.LoggingConfig.Level = logp.DebugLevel
	internal, err := logger.MakeInternalFileOutput(cfg.Settings.LoggingConfig)
	if err != nil {
		return nil, err
	}

	libC, err := logger.ToCommonConfig(cfg.Settings.LoggingConfig)
	if err != nil {
		return nil, err
	}

	if err := configure.LoggingWithOutputs("", libC, internal); err != nil {
		return nil, fmt.Errorf("error initializing logging: %w", err)
	}
	return logp.NewLogger(""), nil
}

func getConfig(streams *cli.IOStreams) *configuration.Configuration {
	defaultCfg := configuration.DefaultConfiguration()

	pathConfigFile := paths.ConfigFile()
	rawConfig, err := config.LoadFile(pathConfigFile)
	if err != nil {
		fmt.Fprintf(streams.Err, "could not read configuration file %s", pathConfigFile)
		return defaultCfg
	}

	cfg, err := configuration.NewFromConfig(rawConfig)
	if err != nil {
		fmt.Fprintf(streams.Err, "could not parse configuration file %s", pathConfigFile)
		return defaultCfg
	}

	return cfg
}
