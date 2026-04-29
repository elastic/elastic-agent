// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package upgrade

import (
	"context"
	goerrors "errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/details"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

// ReconcileMismatchedUpgrade reconciles on-disk upgrade state when the running
// agent matches marker.PrevHash rather than marker.Hash. It mirrors the shape
// of RollbackWithOpts: take over the watcher, align the active install,
// remove the versioned home referenced by the marker, then rewrite the marker
// as state=Failed so the failure is reported to Fleet via the normal
// upgrade-details path.
//
// homeRelPath is the running agent's versioned home, relative to topDir.
// runningHash is the running agent's commit (truncated or full). The marker
// is mutated in place and saved to disk.
//
// Operations are idempotent and best-effort: errors are accumulated and
// returned via errors.Join so the caller can continue startup.
func ReconcileMismatchedUpgrade(
	ctx context.Context,
	log *logger.Logger,
	helper WatcherHelper,
	topDir, homeRelPath, runningHash string,
	marker *UpdateMarker,
) error {
	// Take over (terminate + lock) any running watcher so it doesn't act on
	// the marker we're about to rewrite. If takeover fails, an orphan watcher
	// may still operate on its in-memory snapshot of the marker — including
	// running Cleanup against marker.VersionedHome, which can delete the
	// active install. There is no defense from the daemon side once the
	// watcher is past its terminal-state check; the structural fix is in the
	// watcher's cleanup path (see https://github.com/elastic/elastic-agent/issues/13505).
	if lock, err := helper.TakeOverWatcher(ctx, log, topDir); err == nil {
		defer func() {
			if unlockErr := lock.Unlock(); unlockErr != nil {
				log.Warnw("failed releasing watcher lock", "error.message", unlockErr.Error())
			}
		}()
	} else {
		log.Warnw("could not take over watcher; proceeding best-effort",
			"error.message", err.Error())
	}

	var errs []error

	// Point the symlink at the running install and write our hash to
	// active.commit. Same primitive rollback uses, with target = us.
	if err := AlignActiveInstall(log, topDir, homeRelPath, runningHash); err != nil {
		errs = append(errs, fmt.Errorf("aligning active install: %w", err))
	}

	// Remove the versioned home the marker points at, if it still exists.
	if marker.VersionedHome != "" {
		markerHome := filepath.Join(topDir, marker.VersionedHome)
		if err := os.RemoveAll(markerHome); err != nil {
			errs = append(errs, fmt.Errorf("removing marker versioned home %q: %w", markerHome, err))
		}
	}

	// Rewrite the marker as state=Failed so the coordinator reports the
	// failure to Fleet. The marker is removed on a subsequent boot once
	// Fleet acks it.
	if marker.Details == nil {
		marker.Details = details.NewDetails(marker.Version, details.StateFailed, marker.GetActionID())
	}
	marker.Details.SetStateWithReason(details.StateFailed, "running agent does not match upgrade marker target")
	if err := SaveMarker(paths.DataFrom(topDir), marker, true); err != nil {
		errs = append(errs, fmt.Errorf("saving failed-state marker: %w", err))
	}

	return goerrors.Join(errs...)
}
