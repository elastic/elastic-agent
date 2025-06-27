// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

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
	"github.com/elastic/elastic-agent/pkg/control/v2/client"

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
			log, err := configuredLogger(cfg, watcherName)
			if err != nil {
				fmt.Fprintf(streams.Err, "Error configuring logger: %v\n%s\n", err, troubleshootMessage())
				os.Exit(3)
			}

			// Make sure to flush any buffered logs before we're done.
			defer log.Sync() //nolint:errcheck // flushing buffered logs is best effort.

			if err := watchCmd(log, paths.Top(), cfg.Settings.Upgrade.Watcher, new(agtWatcherImpl), new(agtInstallationModifierImpl)); err != nil {
				log.Errorw("Watch command failed", "error.message", err)
				fmt.Fprintf(streams.Err, "Watch command failed: %v\n%s\n", err, troubleshootMessage())
				os.Exit(4)
			}
		},
	}

	return cmd
}

type agentWatcher interface {
	Watch(ctx context.Context, tilGrace, errorCheckInterval time.Duration, log *logp.Logger) error
}

type installationModifier interface {
	Cleanup(log *logger.Logger, topDirPath, currentVersionedHome, currentHash string, removeMarker, keepLogs bool) error
	Rollback(ctx context.Context, log *logger.Logger, c client.Client, topDirPath, prevVersionedHome, prevHash string) error
}

func watchCmd(log *logp.Logger, topDir string, cfg *configuration.UpgradeWatcherConfig, watcher agentWatcher, installModifier installationModifier) error {
	log.Infow("Upgrade Watcher started", "process.pid", os.Getpid(), "agent.version", version.GetAgentPackageVersion(), "config", cfg)
	dataDir := paths.DataFrom(topDir)
	marker, err := upgrade.LoadMarker(dataDir)
	if err != nil {
		log.Error("failed to load marker", err)
		return err
	}
	if marker == nil {
		// no marker found we're not in upgrade process
		log.Infof("update marker not present at '%s'", dataDir)
		return nil
	}

	log.With("marker", marker, "details", marker.Details).Info("Loaded update marker")
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

	isWithinGrace, tilGrace := gracePeriod(marker, cfg.GracePeriod)
	if isTerminalState(marker) || !isWithinGrace {
		stateString := ""
		if marker.Details != nil {
			stateString = string(marker.Details.State)
		}
		log.Infof("not within grace [updatedOn %v] %v or agent have been rolled back [state: %s]", marker.UpdatedOn.String(), time.Since(marker.UpdatedOn).String(), stateString)
		// if it is started outside of upgrade loop
		// if we're not within grace and marker is still there it might mean
		// that cleanup was not performed ok, cleanup everything except current version
		// hash is the same as hash of agent which initiated watcher.
		if err := installModifier.Cleanup(log, paths.Top(), paths.VersionedHome(topDir), release.ShortCommit(), true, false); err != nil {
			log.Error("clean up of prior watcher run failed", err)
		}
		// exit nicely
		return nil
	}

	// About to start watching the upgrade. Initialize upgrade details and save them in the
	// upgrade marker.
	saveMarkerFunc := func(marker *upgrade.UpdateMarker, b bool) error {
		return upgrade.SaveMarker(dataDir, marker, b)
	}
	upgradeDetails := initUpgradeDetails(marker, saveMarkerFunc, log)

	errorCheckInterval := cfg.ErrorCheck.Interval
	ctx := context.Background()
	if err := watcher.Watch(ctx, tilGrace, errorCheckInterval, log); err != nil {
		log.Error("Error detected, proceeding to rollback: %v", err)

		upgradeDetails.SetStateWithReason(details.StateRollback, details.ReasonWatchFailed)
		err = installModifier.Rollback(ctx, log, client.New(), paths.Top(), marker.PrevVersionedHome, marker.PrevHash)
		if err != nil {
			log.Error("rollback failed", err)
			upgradeDetails.Fail(err)
		}
		return err
	}

	// watch succeeded - upgrade was successful!
	upgradeDetails.SetState(details.StateCompleted)

	// cleanup older versions,
	// in windows it might leave self untouched, this will get cleaned up
	// later at the start, because for windows we leave marker untouched.
	//
	// Why is this being skipped on Windows? The comment above is not clear.
	// issue: https://github.com/elastic/elastic-agent/issues/3027
	removeMarker := !isWindows()
	err = installModifier.Cleanup(log, topDir, marker.VersionedHome, marker.Hash, removeMarker, false)
	if err != nil {
		log.Error("cleanup after successful watch failed", err)
	}
	return err
}

// isTerminalState returns true if the state in the upgrade marker contains details and the upgrade details state is a
// terminal one: UPG_COMPLETE, UPG_ROLLBACK and UPG_FAILED
// If the upgrade marker or the upgrade marker details are nil the function will return false: as
// no state is specified, having simply a marker without details would mean that some upgrade operation is ongoing
// (probably initiated by an older agent).
func isTerminalState(marker *upgrade.UpdateMarker) bool {
	if marker.Details == nil {
		return false
	}

	switch marker.Details.State {
	case details.StateCompleted, details.StateRollback, details.StateFailed:
		return true
	default:
		return false
	}
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

func configuredLogger(cfg *configuration.Configuration, name string) (*logger.Logger, error) {
	cfg.Settings.LoggingConfig.Beat = name
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

func initUpgradeDetails(marker *upgrade.UpdateMarker, saveMarker func(*upgrade.UpdateMarker, bool) error, log *logp.Logger) *details.Details {
	upgradeDetails := details.NewDetails(version.GetAgentPackageVersion(), details.StateWatching, marker.GetActionID())
	upgradeDetails.RegisterObserver(func(details *details.Details) {
		marker.Details = details
		if err := saveMarker(marker, true); err != nil {
			if details != nil {
				log.Errorf("unable to save upgrade marker after setting upgrade details (state = %s): %s", details.State, err.Error())
			} else {
				log.Errorf("unable to save upgrade marker after clearing upgrade details: %s", err.Error())
			}
		}
	})

	return upgradeDetails
}
