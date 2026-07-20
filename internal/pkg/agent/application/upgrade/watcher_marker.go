// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package upgrade

import (
	goerrors "errors"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/pkg/core/logger"
	"github.com/elastic/elastic-agent/pkg/upgrade/details"
	"github.com/elastic/elastic-agent/version"
)

const watcherMarkerFilename = ".watcher-marker"

// WatcherMarker records the terminal outcome of an upgrade. Written exclusively
// by the watcher; read-only for the agent and coordinator. Persists after the
// upgrade marker is removed and is overwritten by the next upgrade cycle.
type WatcherMarker struct {
	// Outcome is the terminal state: completed, rolled back, or failed.
	Outcome details.State `yaml:"outcome"`

	// TargetVersion is the version this upgrade attempted to reach.
	TargetVersion string `yaml:"target_version"`
	// PreviousVersion is the version the agent upgraded from.
	PreviousVersion string `yaml:"previous_version"`
	// ActionID is the Fleet action that triggered this upgrade, or "" for
	// locally-triggered upgrades. Used to distinguish retries to the same version.
	ActionID string `yaml:"action_id"`

	// Reason is set when Outcome is StateRollback.
	Reason string `yaml:"reason,omitempty"`
	// ErrorMsg is set when Outcome is StateFailed.
	ErrorMsg string `yaml:"error_msg,omitempty"`

	// CompletedAt is when the watcher reached this outcome.
	CompletedAt time.Time `yaml:"completed_at"`
	// WatcherVersion is the watcher binary version that wrote this record. Diagnostic only.
	WatcherVersion string `yaml:"watcher_version,omitempty"`
}

// WriteWatcherMarker writes the marker to disk, overwriting any previous record.
func WriteWatcherMarker(log *logger.Logger, dataDirPath string, wm *WatcherMarker) error {
	if wm.WatcherVersion == "" {
		wm.WatcherVersion = version.GetAgentPackageVersion()
	}

	wmBytes, err := yaml.Marshal(wm)
	if err != nil {
		return errors.New(err, errors.TypeConfig, "failed to marshal watcher marker")
	}

	wmPath := watcherMarkerFilePath(dataDirPath)
	log.Infow("Writing watcher marker file", "file.path", wmPath, "outcome", wm.Outcome, "target_version", wm.TargetVersion)
	if err := writeMarkerFile(wmPath, wmBytes, true); err != nil {
		return goerrors.Join(err, errors.New(errors.TypeFilesystem, "failed to write watcher marker file", errors.M(errors.MetaKeyPath, wmPath)))
	}

	return nil
}

// LoadWatcherMarker loads the most recently recorded watcher marker, or returns nil if none exists.
func LoadWatcherMarker(dataDirPath string) (*WatcherMarker, error) {
	wmBytes, err := readMarkerFile(watcherMarkerFilePath(dataDirPath))
	if err != nil {
		return nil, err
	}
	if wmBytes == nil {
		return nil, nil
	}

	wm := &WatcherMarker{}
	if err := yaml.Unmarshal(wmBytes, wm); err != nil {
		return nil, err
	}

	return wm, nil
}

func watcherMarkerFilePath(dataDirPath string) string {
	return filepath.Join(dataDirPath, watcherMarkerFilename)
}
