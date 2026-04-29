// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

// This file consolidates upgrade-marker reconciliation logic — both the
// standalone functions (ReconcileMismatchedUpgrade, DiscardStaleMarker) used
// from cmd.handleUpgrade on the next-boot path, and the (Upgrader)-method
// helpers (abortUpgrade, reconcileFailedUpgrade) used from upgrade.Upgrade()'s
// error paths. The methods on Upgrader live here rather than in upgrade.go
// because they are exclusively about reconciliation; cohesion of the
// reconciliation surface in one file is preferred over having all methods
// of a type in the file where the type is declared.

package upgrade

import (
	"context"
	goerrors "errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/details"
	"github.com/elastic/elastic-agent/internal/pkg/release"
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
	// the marker we're about to rewrite. The data-loss hazard if takeover
	// fails (orphan watcher running Cleanup against a stale
	// marker.VersionedHome) is covered structurally by the keep-list guard
	// in upgrade.cleanup, which always preserves the directory backing the
	// live agent symlink. Takeover here is still preferable so the orphan
	// doesn't observe the in-flight reconcile and report misleading state
	// to Fleet — but it is best-effort, not load-bearing.
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

// DiscardStaleMarker removes an upgrade marker that doesn't describe the
// running agent or any version we recognize. Conservative: takes the watcher
// lock so an orphan can't act on the marker, but doesn't touch versioned
// homes since we don't know what they refer to. Just removes the misleading
// metadata so it doesn't keep tripping startup logic.
func DiscardStaleMarker(ctx context.Context, log *logger.Logger, helper WatcherHelper, topDir string) error {
	if lock, err := helper.TakeOverWatcher(ctx, log, topDir); err == nil {
		defer func() { _ = lock.Unlock() }()
	} else {
		log.Warnw("could not take over watcher when discarding stale marker",
			"error.message", err.Error())
	}

	if err := CleanMarker(log, paths.DataFrom(topDir)); err != nil {
		return fmt.Errorf("clearing stale marker: %w", err)
	}
	return nil
}

// abortUpgrade undoes an in-progress upgrade and reconciles any on-disk
// marker so the failure is reportable to Fleet. Combines the physical undo
// (rollbackInstall: symlink revert, new home removal, TTL clear) with the
// marker reconcile (rewrite as state=Failed, align active.commit). Returns
// the physical-undo error; reconcile failures are logged best-effort and
// don't shadow the original failure.
//
// newHomeRelPath is the partial new install (relative to topDir) being undone.
// currentHomeRelPath is the running agent's home (relative to topDir) — i.e.
// the install we want to keep.
//
// Used by every error path in Upgrade() that occurs after the symlink has
// been flipped, so callers don't need to remember to combine the two steps.
func (u *Upgrader) abortUpgrade(ctx context.Context, newHomeRelPath, currentHomeRelPath string) error {
	rollbackErr := u.rollbackInstall(ctx, u.log, paths.Top(), newHomeRelPath, currentHomeRelPath, u.availableRollbacksSource)
	u.reconcileFailedUpgrade(ctx, currentHomeRelPath)
	return rollbackErr
}

// reconcileFailedUpgrade reconciles any on-disk upgrade marker after an
// aborted upgrade. If a marker is present, it is rewritten as state=Failed
// and the on-disk state (symlink, active.commit) is realigned with the
// running agent so the failure is reportable to Fleet via the existing
// upgrade-details path. Best-effort: errors are logged, never returned.
//
// currentHomeRelPath is the running agent's home (relative to topDir).
//
// Called from Upgrade()'s rollback paths after rollbackInstall has done the
// physical undo. Composes with the next-boot reconcile in handleUpgrade so
// that residual cases (SIGKILL between marker write and this call,
// LoadMarker failures, etc.) still get caught later.
func (u *Upgrader) reconcileFailedUpgrade(ctx context.Context, currentHomeRelPath string) {
	marker, err := LoadMarker(paths.Data())
	if err != nil {
		u.log.Warnw("could not load marker after upgrade failure; reconcile deferred to next boot",
			"error.message", err.Error())
		return
	}
	if marker == nil {
		return
	}
	if reconcileErr := ReconcileMismatchedUpgrade(
		ctx, u.log, u.watcherHelper,
		paths.Top(), currentHomeRelPath, release.Commit(),
		marker,
	); reconcileErr != nil {
		u.log.Warnw("failed to reconcile upgrade marker after failure",
			"error.message", reconcileErr.Error())
	}
}
