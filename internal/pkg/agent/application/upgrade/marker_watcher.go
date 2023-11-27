// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package upgrade

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/fsnotify/fsnotify"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/details"
	"github.com/elastic/elastic-agent/pkg/core/logger"
	"github.com/elastic/elastic-agent/version"
)

type MarkerWatcher interface {
	Watch() <-chan UpdateMarker
	Run(ctx context.Context) error
}

type MarkerFileWatcher struct {
	markerFilePath string
	logger         *logger.Logger
	updateCh       chan UpdateMarker
}

func newMarkerFileWatcher(upgradeMarkerFilePath string, logger *logger.Logger) MarkerWatcher {
	logger = logger.Named("marker_file_watcher")

	return &MarkerFileWatcher{
		markerFilePath: upgradeMarkerFilePath,
		logger:         logger,
		updateCh:       make(chan UpdateMarker),
	}
}

func (mfw *MarkerFileWatcher) Watch() <-chan UpdateMarker {
	return mfw.updateCh
}

func (mfw *MarkerFileWatcher) Run(ctx context.Context) error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("failed to create upgrade marker watcher: %w", err)
	}

	// Watch the upgrade marker file's directory, not the file itself, so we
	// notice the file even if it's deleted and recreated.
	upgradeMarkerDirPath := filepath.Dir(mfw.markerFilePath)
	if err := watcher.Add(upgradeMarkerDirPath); err != nil {
		return fmt.Errorf("failed to set watch on upgrade marker's directory [%s]: %w", upgradeMarkerDirPath, err)
	}

	// Do an initial read from the upgrade marker file, in case the file
	// is already present before the watching starts.
	doInitialRead := make(chan struct{}, 1)
	doInitialRead <- struct{}{}

	// Handle watching
	go func() {
		defer watcher.Close()
		for {
			select {
			case <-ctx.Done():
				return
			case err, ok := <-watcher.Errors:
				if !ok { // Channel was closed (i.e. Watcher.Close() was called).
					mfw.logger.Debug("fsnotify.Watcher's error channel was closed")
					return
				}
				mfw.logger.Errorf("upgrade marker watch returned error: %s", err)
				continue
			case e, ok := <-watcher.Events:
				if !ok { // Channel was closed (i.e. Watcher.Close() was called).
					mfw.logger.Debug("fsnotify.Watcher's events channel was closed")
					return
				}

				if e.Name != mfw.markerFilePath {
					// Since we are watching the directory that will contain the upgrade
					// marker file, we could receive events here for changes to files other
					// than the upgrade marker. We ignore such events as we're only concerned
					// with changes to the upgrade marker.
					continue
				}

				switch {
				case e.Op&(fsnotify.Create|fsnotify.Write) != 0:
					// Upgrade marker file was created or updated; read its contents
					// and send them over the update channel.
					mfw.processMarker(version.GetAgentPackageVersion())
				}
			case <-doInitialRead:
				mfw.processMarker(version.GetAgentPackageVersion())
			}
		}
	}()

	return nil
}

func (mfw *MarkerFileWatcher) processMarker(currentVersion string) {
	marker, err := loadMarker(mfw.markerFilePath)
	if err != nil {
		mfw.logger.Error(err)
		return
	}

	// Nothing to do if marker is not (yet) present
	if marker == nil {
		return
	}

	// If the marker exists but the version of Agent we're running right
	// now is the same as the prevVersion recorded in the marker, it means
	// the upgrade was rolled back. Ideally, this UPG_ROLLBACK state would've
	// been recorded in the marker's upgrade details field but, in case it
	// isn't for some reason, we fallback to explicitly setting that state as
	// part of the upgrade details in the marker.
	if marker.PrevVersion == currentVersion {
		if marker.Details == nil {
			marker.Details = details.NewDetails("unknown", details.StateRollback, marker.GetActionID())
		} else {
			marker.Details.SetState(details.StateRollback)
		}
	}

	mfw.updateCh <- *marker
}
