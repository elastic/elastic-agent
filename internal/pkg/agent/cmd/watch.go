// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package cmd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/spf13/cobra"

	semver "github.com/elastic/elastic-agent/pkg/version"

	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/elastic-agent-libs/logp/configure"
	"github.com/elastic/elastic-agent/pkg/control/v2/client"
	"github.com/elastic/elastic-agent/pkg/utils"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/filelock"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/details"
	"github.com/elastic/elastic-agent/internal/pkg/agent/configuration"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/internal/pkg/cli"
	"github.com/elastic/elastic-agent/internal/pkg/config"
	"github.com/elastic/elastic-agent/pkg/core/logger"
	"github.com/elastic/elastic-agent/version"
)

const (
	watcherName     = "elastic-agent-watcher"
	watcherLockFile = "watcher.lock"

	// flag names
	takedownFlagName      = "takedown"
	takedownFlagShorthand = "t"

	rollbackFlagName      = "rollback"
	rollbackFlagShorthand = "r"

	// error exit codes
	errorSettingParentSignalsExitCode = 6
	errorRollbackToValue              = 7
	errorRollbackFailed               = 8
)

// watcherPIDsFetcher defines the type of function responsible for fetching watcher PIDs.
// This will allow for easier testing of takeOverWatcher using fake binaries
type watcherPIDsFetcher func() ([]int, error)

var ErrWatchCancelled = errors.New("watch cancelled")

func newWatchCommandWithArgs(_ []string, streams *cli.IOStreams) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "watch",
		Short: "Watch the Elastic Agent for failures and initiate rollback",
		Long:  `This command watches Elastic Agent for failures and initiates rollback if necessary.`,
		Run: func(c *cobra.Command, _ []string) {
			cfg := getConfig(streams)
			log, err := configuredLogger(cfg, watcherName)
			if err != nil {
				fmt.Fprintf(streams.Err, "Error configuring logger: %v\n%s\n", err, troubleshootMessage)
				os.Exit(3)
			}

			// Make sure to flush any buffered logs before we're done.
			defer log.Sync() //nolint:errcheck // flushing buffered logs is best effort.

			err = setupParentProcessSignals()
			if err != nil {
				fmt.Fprintf(streams.Err, "Error setting parent process signals: %v\n", err)
				os.Exit(errorSettingParentSignalsExitCode)
			}

			takedown, _ := c.Flags().GetBool(takedownFlagName)
			if takedown {
				err = takedownWatcher(context.Background(), log, utils.GetWatcherPIDs)
				if err != nil {
					log.Errorf("error taking down watcher: %v", err)
					os.Exit(5)
				}
				return
			}

			if c.Flags().Changed(rollbackFlagName) {
				// rollback-to has been specified on command line
				rollbackTo, _ := c.Flags().GetString(rollbackFlagName)
				if rollbackTo == "" {
					fmt.Fprintf(streams.Err, "%s flag value cannot be empty", rollbackFlagName)
					os.Exit(errorRollbackToValue)
				}
				if err = withAppLocker(log, func() error {
					return rollback(log, paths.Top(), client.New(), new(upgradeInstallationModifier), rollbackTo)
				}); err != nil {
					log.Errorw("Rollback command failed", "error.message", err)
					fmt.Fprintf(streams.Err, "Rollback command failed: %v\n", err)
					os.Exit(errorRollbackFailed)
				}
				return
			}

			if err = withAppLocker(log, func() error {
				return watchCmd(log, paths.Top(), cfg.Settings.Upgrade.Watcher, new(upgradeAgentWatcher), new(upgradeInstallationModifier))
			}); err != nil {
				log.Errorw("Watch command failed", "error.message", err)
				fmt.Fprintf(streams.Err, "Watch command failed: %v\n%s\n", err, troubleshootMessage)
				os.Exit(4)
			}
		},
	}
	cmd.Flags().BoolP(takedownFlagName, takedownFlagShorthand, false, "Take down the running watcher")
	_ = cmd.Flags().MarkHidden(takedownFlagName)
	cmd.Flags().StringP(rollbackFlagName, rollbackFlagShorthand, "", "Versioned home to roll back to")
	_ = cmd.Flags().MarkHidden(rollbackFlagName)
	return cmd
}

type agentWatcher interface {
	Watch(ctx context.Context, tilGrace, errorCheckInterval time.Duration, log *logp.Logger) error
}

func WithPreRestartHook(preRestartHook upgrade.RollbackHook) upgrade.RollbackOption {
	return func(ros upgrade.RollbackOptionSetter) {
		ros.SetPreRestartHook(preRestartHook)
	}
}

func WithSkipCleanup(skipCleanup bool) upgrade.RollbackOption {
	return func(ros upgrade.RollbackOptionSetter) {
		ros.SetSkipCleanup(skipCleanup)
	}
}

func WithSkipRestart(skipRestart bool) upgrade.RollbackOption {
	return func(ros upgrade.RollbackOptionSetter) {
		ros.SetSkipRestart(skipRestart)
	}
}

func WithRemoveMarker(removeMarker bool) upgrade.RollbackOption {
	return func(ros upgrade.RollbackOptionSetter) {
		ros.SetRemoveMarker(removeMarker)
	}
}

type installationModifier interface {
	Cleanup(log *logger.Logger, topDirPath string, removeMarker, keepLogs bool, versionedHomesToKeep ...string) error
	Rollback(ctx context.Context, log *logger.Logger, c client.Client, topDirPath, prevVersionedHome, prevHash string, opts ...upgrade.RollbackOption) error
}

func withAppLocker(log *logp.Logger, f func() error) error {
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

	return f()
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
		versionedHomesToKeep := make([]string, 0, len(marker.RollbacksAvailable)+1)
		// current version needs to be kept
		if marker.Details != nil && marker.Details.State == details.StateRollback {
			// we need to keep the previous versioned home (we have rolled back)
			versionedHomesToKeep = append(versionedHomesToKeep, marker.PrevVersionedHome)
		} else {
			// we need to keep the upgraded version, since it has not been rolled back
			absCurrentVersionedHome := paths.VersionedHome(topDir)
			currentVersionedHome, err := filepath.Rel(topDir, absCurrentVersionedHome)
			if err != nil {
				return fmt.Errorf("extracting current home path %q relative to %q: %w", absCurrentVersionedHome, topDir, err)
			}
			versionedHomesToKeep = append(versionedHomesToKeep, currentVersionedHome)
		}

		versionedHomesToKeep = appendAvailableRollbacks(log, marker, versionedHomesToKeep)
		log.Infof("About to clean up upgrade. Keeping versioned homes: %v", versionedHomesToKeep)
		if err := installModifier.Cleanup(log, paths.Top(), true, false, versionedHomesToKeep...); err != nil {
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
		if errors.Is(err, ErrWatchCancelled) {
			// the watch has been cancelled prematurely, don't clean or rollback just yet
			return nil
		}

		log.Error("Error detected, proceeding to rollback: %v", err)

		upgradeDetails.SetStateWithReason(details.StateRollback, details.ReasonWatchFailed)

		// by default remove marker (backward compatible behaviour)
		removeMarker := true

		previousVersion, versionParseErr := semver.ParseVersion(marker.PrevVersion)
		if versionParseErr != nil {
			log.Errorf("could not parse previous version %s: %s", marker.PrevVersion, versionParseErr)
		} else if !previousVersion.Less(*semver.NewParsedSemVer(9, 2, 0, "SNAPSHOT", "")) {
			// leave the marker in place when rolling back to agent >= 9.2.0-SNAPSHOT as it will be used to determine
			// that agent was rolled back and the reason
			removeMarker = false
		}
		err = installModifier.Rollback(ctx, log, client.New(), paths.Top(), marker.PrevVersionedHome, marker.PrevHash, WithRemoveMarker(removeMarker))
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
	newVersionedHome := marker.VersionedHome
	if newVersionedHome == "" {
		// the upgrade marker may have been created by an older version of agent where the versionedHome is always `data/elastic-agent-<shortHash>`
		newVersionedHome = filepath.Join("data", fmt.Sprintf("elastic-agent-%s", marker.Hash[:6]))
	}
	versionedHomesToKeep := make([]string, 0, len(marker.RollbacksAvailable)+1)
	versionedHomesToKeep = append(versionedHomesToKeep, newVersionedHome)
	versionedHomesToKeep = appendAvailableRollbacks(log, marker, versionedHomesToKeep)

	err = installModifier.Cleanup(log, topDir, removeMarker, false, versionedHomesToKeep...)
	if err != nil {
		log.Error("cleanup after successful watch failed", err)
	}
	return err
}

func appendAvailableRollbacks(log *logp.Logger, marker *upgrade.UpdateMarker, versionedHomesToKeep []string) []string {
	// add any available rollbacks
	for versionedHome, ra := range marker.RollbacksAvailable {
		log.Debugf("Adding available rollback %s:%+v to the directories to keep during cleanup", versionedHome, ra)
		versionedHomesToKeep = append(versionedHomesToKeep, versionedHome)
	}
	return versionedHomesToKeep
}

func rollback(log *logp.Logger, topDir string, client client.Client, installModifier installationModifier, versionedHome string) error {
	// TODO: there should be some sanity check in rollback functions like the installation we are going back to should exist and work
	log.Infof("rolling back to %s", versionedHome)
	dataDir := paths.DataFrom(topDir)
	marker, err := upgrade.LoadMarker(dataDir)
	if err != nil {
		log.Error("failed to load marker", err)
		return err
	}
	if marker == nil {
		// no marker found we're not in upgrade process, recreate one marker to track the rollback
		marker = &upgrade.UpdateMarker{}
		log.Info("No update marker found, recreating an empty one to track the rollback")
	} else {
		log.With("marker", marker, "details", marker.Details).Info("Loaded update marker")
	}

	updateMarkerAndDetails := func(_ context.Context, _ *logger.Logger, _ string) error {
		if marker.Details == nil {
			actionID := ""
			if marker.Action != nil {
				actionID = marker.Action.ActionID
			}
			marker.Details = details.NewDetails(marker.Version, details.StateRollback, actionID)
		}
		// use the previous version from the marker
		marker.Details.SetStateWithReason(details.StateRollback, fmt.Sprintf(details.ReasonManualRollbackPattern, marker.PrevVersion))
		err = upgrade.SaveMarker(dataDir, marker, true)
		if err != nil {
			return fmt.Errorf("saving marker after rolling back: %w", err)
		}
		return nil
	}

	// FIXME get the hash from the list of installs or the manifest or the versioned home
	// This is only a placeholder in case there is no versionedHome defined (which we always have)
	hash := ""
	if filepath.IsAbs(versionedHome) {
		// if the versioned home is an absolute path we need to normalize it relative to the current topDir as the
		// cleanup() will expect relative paths
		versionedHome, err = filepath.Rel(topDir, versionedHome)
		if err != nil {
			return fmt.Errorf("extract from %q a path relative to %q: %w", versionedHome, topDir, err)
		}
	}
	err = installModifier.Rollback(context.Background(), log, client, topDir, versionedHome, hash, WithPreRestartHook(updateMarkerAndDetails))
	if err != nil {
		return fmt.Errorf("rolling back: %w", err)
	}

	return nil
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
