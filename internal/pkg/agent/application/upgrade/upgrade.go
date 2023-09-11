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

	"github.com/otiai10/copy"
	"go.elastic.co/apm"

	"github.com/elastic/elastic-agent/internal/pkg/config"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/reexec"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi/acker"
	"github.com/elastic/elastic-agent/internal/pkg/release"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

const (
	agentName       = "elastic-agent"
	hashLen         = 6
	agentCommitFile = ".elastic-agent.active.commit"
	runDirMod       = 0770
)

var agentArtifact = artifact.Artifact{
	Name:     "Elastic Agent",
	Cmd:      agentName,
	Artifact: "beats/" + agentName,
}

// ErrSameVersion error is returned when the upgrade results in the same installed version.
var ErrSameVersion = errors.New("upgrade did not occur because its the same version")

// Upgrader performs an upgrade
type Upgrader struct {
	log         *logger.Logger
	settings    *artifact.Config
	agentInfo   *info.AgentInfo
	upgradeable bool
}

// IsUpgradeable when agent is installed and running as a service or flag was provided.
func IsUpgradeable() bool {
	// only upgradeable if running from Agent installer and running under the
	// control of the system supervisor (or built specifically with upgrading enabled)
	return release.Upgradeable() || (info.RunningInstalled() && info.RunningUnderSupervisor())
}

// NewUpgrader creates an upgrader which is capable of performing upgrade operation
func NewUpgrader(log *logger.Logger, settings *artifact.Config, agentInfo *info.AgentInfo) *Upgrader {
	return &Upgrader{
		log:         log,
		settings:    settings,
		agentInfo:   agentInfo,
		upgradeable: IsUpgradeable(),
	}
}

// Reload reloads the artifact configuration for the upgrader.
func (u *Upgrader) Reload(rawConfig *config.Config) error {
	type reloadConfig struct {
		// SourceURI: source of the artifacts, e.g https://artifacts.elastic.co/downloads/
		SourceURI string `json:"agent.download.sourceURI" config:"agent.download.sourceURI"`

		// FleetSourceURI: source of the artifacts, e.g https://artifacts.elastic.co/downloads/ coming from fleet which uses
		// different naming.
		FleetSourceURI string `json:"agent.download.source_uri" config:"agent.download.source_uri"`
	}
	cfg := &reloadConfig{}
	if err := rawConfig.Unpack(&cfg); err != nil {
		return errors.New(err, "failed to unpack config during reload")
	}

	var newSourceURI string
	if cfg.FleetSourceURI != "" {
		// fleet configuration takes precedence
		newSourceURI = cfg.FleetSourceURI
	} else if cfg.SourceURI != "" {
		newSourceURI = cfg.SourceURI
	}

	if newSourceURI != "" {
		u.log.Infof("Source URI changed from %q to %q", u.settings.SourceURI, newSourceURI)
		u.settings.SourceURI = newSourceURI
	} else {
		// source uri unset, reset to default
		u.log.Infof("Source URI reset from %q to %q", u.settings.SourceURI, artifact.DefaultSourceURI)
		u.settings.SourceURI = artifact.DefaultSourceURI
	}
	return nil
}

// Upgradeable returns true if the Elastic Agent can be upgraded.
func (u *Upgrader) Upgradeable() bool {
	return u.upgradeable
}

// Upgrade upgrades running agent, function returns shutdown callback that must be called by reexec.
func (u *Upgrader) Upgrade(ctx context.Context, version string, sourceURI string, action *fleetapi.ActionUpgrade, skipVerifyOverride bool, skipDefaultPgp bool, pgpBytes ...string) (_ reexec.ShutdownCallbackFn, err error) {
	u.log.Infow("Upgrading agent", "version", version, "source_uri", sourceURI)
	span, ctx := apm.StartSpan(ctx, "upgrade", "app.internal")
	defer span.End()

	err = cleanNonMatchingVersionsFromDownloads(u.log, u.agentInfo.Version())
	if err != nil {
		u.log.Errorw("Unable to clean downloads before update", "error.message", err, "downloads.path", paths.Downloads())
	}

	sourceURI = u.sourceURI(sourceURI)
	archivePath, err := u.downloadArtifact(ctx, version, sourceURI, skipVerifyOverride, skipDefaultPgp, pgpBytes...)
	if err != nil {
		// Run the same pre-upgrade cleanup task to get rid of any newly downloaded files
		// This may have an issue if users are upgrading to the same version number.
		if dErr := cleanNonMatchingVersionsFromDownloads(u.log, u.agentInfo.Version()); dErr != nil {
			u.log.Errorw("Unable to remove file after verification failure", "error.message", dErr)
		}
		return nil, err
	}

	newHash, err := u.unpack(version, archivePath)
	if err != nil {
		return nil, err
	}

	if newHash == "" {
		return nil, errors.New("unknown hash")
	}

	if strings.HasPrefix(release.Commit(), newHash) {
		u.log.Warn("Upgrade action skipped: upgrade did not occur because its the same version")
		return nil, nil
	}

	if err := copyActionStore(u.log, newHash); err != nil {
		return nil, errors.New(err, "failed to copy action store")
	}

	if err := copyRunDirectory(u.log, newHash); err != nil {
		return nil, errors.New(err, "failed to copy run directory")
	}

	if err := ChangeSymlink(ctx, u.log, newHash); err != nil {
		u.log.Errorw("Rolling back: changing symlink failed", "error.message", err)
		rollbackInstall(ctx, u.log, newHash)
		return nil, err
	}

	if err := u.markUpgrade(ctx, u.log, newHash, action); err != nil {
		u.log.Errorw("Rolling back: marking upgrade failed", "error.message", err)
		rollbackInstall(ctx, u.log, newHash)
		return nil, err
	}

	if err := InvokeWatcher(u.log); err != nil {
		u.log.Errorw("Rolling back: starting watcher failed", "error.message", err)
		rollbackInstall(ctx, u.log, newHash)
		return nil, err
	}

	cb := shutdownCallback(u.log, paths.Home(), release.Version(), version, release.TrimCommit(newHash))

	// Clean everything from the downloads dir
	u.log.Infow("Removing downloads directory", "file.path", paths.Downloads())
	err = os.RemoveAll(paths.Downloads())
	if err != nil {
		u.log.Errorw("Unable to clean downloads after update", "error.message", err, "file.path", paths.Downloads())
	}

	return cb, nil
}

// Ack acks last upgrade action
func (u *Upgrader) Ack(ctx context.Context, acker acker.Acker) error {
	// get upgrade action
	marker, err := LoadMarker()
	if err != nil {
		return err
	}
	if marker == nil {
		return nil
	}

	if marker.Acked {
		return nil
	}

	// Action can be nil if the upgrade was called locally.
	// Should handle gracefully
	// https://github.com/elastic/elastic-agent/issues/1788
	if marker.Action != nil {
		if err := acker.Ack(ctx, marker.Action); err != nil {
			return err
		}

		if err := acker.Commit(ctx); err != nil {
			return err
		}
	}

	marker.Acked = true

	return saveMarker(marker)
}

func (u *Upgrader) sourceURI(retrievedURI string) string {
	if retrievedURI != "" {
		return retrievedURI
	}

	return u.settings.SourceURI
}

func rollbackInstall(ctx context.Context, log *logger.Logger, hash string) {
	os.RemoveAll(filepath.Join(paths.Data(), fmt.Sprintf("%s-%s", agentName, hash)))
	_ = ChangeSymlink(ctx, log, release.ShortCommit())
}

func copyActionStore(log *logger.Logger, newHash string) error {
	// copies legacy action_store.yml, state.yml and state.enc encrypted file if exists
	storePaths := []string{paths.AgentActionStoreFile(), paths.AgentStateStoreYmlFile(), paths.AgentStateStoreFile()}
	newHome := filepath.Join(filepath.Dir(paths.Home()), fmt.Sprintf("%s-%s", agentName, newHash))
	log.Infow("Copying action store", "new_home_path", newHome)

	for _, currentActionStorePath := range storePaths {
		newActionStorePath := filepath.Join(newHome, filepath.Base(currentActionStorePath))
		log.Infow("Copying action store path", "from", currentActionStorePath, "to", newActionStorePath)
		currentActionStore, err := os.ReadFile(currentActionStorePath)
		if os.IsNotExist(err) {
			// nothing to copy
			continue
		}
		if err != nil {
			return err
		}

		if err := os.WriteFile(newActionStorePath, currentActionStore, 0o600); err != nil {
			return err
		}
	}

	return nil
}

func copyRunDirectory(log *logger.Logger, newHash string) error {
	newRunPath := filepath.Join(filepath.Dir(paths.Home()), fmt.Sprintf("%s-%s", agentName, newHash), "run")
	oldRunPath := filepath.Join(filepath.Dir(paths.Home()), fmt.Sprintf("%s-%s", agentName, release.ShortCommit()), "run")

	log.Infow("Copying run directory", "new_run_path", newRunPath, "old_run_path", oldRunPath)

	if err := os.MkdirAll(newRunPath, runDirMod); err != nil {
		return errors.New(err, "failed to create run directory")
	}

	err := copyDir(log, oldRunPath, newRunPath, true)
	if os.IsNotExist(err) {
		// nothing to copy, operation ok
		log.Infow("Run directory not present", "old_run_path", oldRunPath)
		return nil
	}
	if err != nil {
		return errors.New(err, "failed to copy %q to %q", oldRunPath, newRunPath)
	}

	return nil
}

// shutdownCallback returns a callback function to be executing during shutdown once all processes are closed.
// this goes through runtime directory of agent and copies all the state files created by processes to new versioned
// home directory with updated process name to match new version.
func shutdownCallback(l *logger.Logger, homePath, prevVersion, newVersion, newHash string) reexec.ShutdownCallbackFn {
	if release.Snapshot() {
		// SNAPSHOT is part of newVersion
		prevVersion += "-SNAPSHOT"
	}

	return func() error {
		runtimeDir := filepath.Join(homePath, "run")
		processDirs, err := readProcessDirs(runtimeDir)
		if err != nil {
			return err
		}

		oldHome := homePath
		newHome := filepath.Join(filepath.Dir(homePath), fmt.Sprintf("%s-%s", agentName, newHash))
		for _, processDir := range processDirs {
			newDir := strings.ReplaceAll(processDir, prevVersion, newVersion)
			newDir = strings.ReplaceAll(newDir, oldHome, newHome)
			if err := copyDir(l, processDir, newDir, true); err != nil {
				return err
			}
		}
		return nil
	}
}

func readProcessDirs(runtimeDir string) ([]string, error) {
	pipelines, err := readDirs(runtimeDir)
	if err != nil {
		return nil, err
	}

	processDirs := make([]string, 0)
	for _, p := range pipelines {
		dirs, err := readDirs(p)
		if err != nil {
			return nil, err
		}

		processDirs = append(processDirs, dirs...)
	}

	return processDirs, nil
}

// readDirs returns list of absolute paths to directories inside specified path.
func readDirs(dir string) ([]string, error) {
	dirEntries, err := os.ReadDir(dir)
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}

	dirs := make([]string, 0, len(dirEntries))
	for _, de := range dirEntries {
		if !de.IsDir() {
			continue
		}

		dirs = append(dirs, filepath.Join(dir, de.Name()))
	}

	return dirs, nil
}

func copyDir(l *logger.Logger, from, to string, ignoreErrs bool) error {
	var onErr func(src, dst string, err error) error

	if ignoreErrs {
		onErr = func(src, dst string, err error) error {
			if err == nil {
				return nil
			}

			// ignore all errors, just log them
			l.Infof("ignoring error: failed to copy %q to %q: %s", src, dst, err.Error())
			return nil
		}
	}

	return copy.Copy(from, to, copy.Options{
		OnSymlink: func(_ string) copy.SymlinkAction {
			return copy.Shallow
		},
		Sync:    true,
		OnError: onErr,
	})
}
