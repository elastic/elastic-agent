// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package upgrade

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/elastic/elastic-agent/pkg/core/logger"

	"github.com/fsnotify/fsnotify"
)

type MarkerWatcher interface {
	Watch() <-chan UpdateMarker
	Errors() <-chan error
	Run(ctx context.Context) error
	Close() error
}

type MarkerFileWatcher struct {
	watcher        *fsnotify.Watcher
	markerFilePath string

	logger *logger.Logger

	updateCh chan UpdateMarker
	errCh    chan error
}

func newMarkerFileWatcher(upgradeMarkerFilePath string, logger *logger.Logger) (MarkerWatcher, error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("failed to create upgrade marker watcher: %w", err)
	} // Watch the upgrade marker file's directory, not the file itself, so we

	// notice the file even if it's deleted and recreated.
	upgradeMarkerDirPath := filepath.Dir(upgradeMarkerFilePath)
	err = watcher.Add(upgradeMarkerDirPath)
	if err != nil {
		return nil, fmt.Errorf("failed to set watch on upgrade marker's directory [%s]: %w", upgradeMarkerDirPath, err)
	}

	// TODO: remove debug logging
	logger.Info("Creating new marker file watcher")
	return &MarkerFileWatcher{
		watcher:        watcher,
		markerFilePath: upgradeMarkerFilePath,
		logger:         logger,
		updateCh:       make(chan UpdateMarker),
		errCh:          make(chan error),
	}, nil
}

func (mfw *MarkerFileWatcher) Watch() <-chan UpdateMarker {
	return mfw.updateCh
}

func (mfw *MarkerFileWatcher) Errors() <-chan error {
	return mfw.errCh
}

func (mfw *MarkerFileWatcher) Run(ctx context.Context) error {
	// Handle watching
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case err, ok := <-mfw.watcher.Errors:
				// TODO: remove debug logging
				mfw.logger.Info("after there are watch errors")
				mfw.logger.Debug("after there are watch errors")
				if !ok { // Channel was closed (i.e. Watcher.Close() was called).
					mfw.logger.Debug("upgrade marker watch's error channel was closed")
					return
				}
				mfw.errCh <- fmt.Errorf("upgrade marker watch returned error: %w", err)
				continue
			case e, ok := <-mfw.watcher.Events:
				// TODO: remove debug logging
				mfw.logger.Infof("after there is a watch event: [%s]", e.String())
				mfw.logger.Debugf("after there is a watch event: [%s]", e.String())
				if !ok { // Channel was closed (i.e. Watcher.Close() was called).
					mfw.logger.Debug("upgrade marker watch's events channel was closed")
					return
				}

				if e.Name != mfw.markerFilePath {
					// Event is for a file other than the upgrade marker; ignore it.
					continue
				}

				switch e.Op {
				case fsnotify.Create, fsnotify.Write:
					// Upgrade marker file was created or updated; read its contents
					// and send them over the update channel.
					// TODO: remove debug logging
					mfw.logger.Info("upgrade marker file created or updated")

					marker, err := loadMarker(mfw.markerFilePath)
					if err != nil {
						mfw.errCh <- fmt.Errorf("unable to load upgrade marker from watch: %w", err)
						return
					}

					mfw.updateCh <- *marker
				}
			}
		}
	}()

	// Do an initial read from the upgrade marker file, in case the file
	// is already present before the watching starts.
	// TODO: remove debug logging
	mfw.logger.Info("initial read of marker file")
	marker, err := loadMarker(mfw.markerFilePath)
	if err != nil {
		return fmt.Errorf("unable to load upgrade marker from watch: %w", err)
	}
	// TODO: remove debug logging
	mfw.logger.Infof("marker: %#+v\n", marker)
	if marker != nil && marker.Details != nil {
		mfw.updateCh <- *marker
	}

	<-ctx.Done()
	return nil
}

func (mfw *MarkerFileWatcher) Close() error {
	return mfw.watcher.Close()
}
