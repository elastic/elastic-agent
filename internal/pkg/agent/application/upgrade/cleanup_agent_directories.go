// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package upgrade

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/ttl"
	"github.com/elastic/elastic-agent/internal/pkg/agent/install"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

// errCleanupDegraded signals that cleanupAgentDirectories completed but with
// degraded verification: the live-install symlink or the upgrade marker could
// not be read, so some conservative directory-preservation decisions were made.
// Callers detect it via errors.Is.
var errCleanupDegraded = errors.New("cleanup completed with degraded verification")

// isDegradedOnly returns true when err wraps errCleanupDegraded and carries no non-degraded
// sibling errors at any level of the error chain.
// For errors.Join results it inspects the join siblings directly; for single-Unwrap wrappers
// (e.g. fmt.Errorf("%w", ...)) it recurses into the wrapped error so that a join nested inside
// a plain wrap is still inspected.
func isDegradedOnly(err error) bool {
	if !errors.Is(err, errCleanupDegraded) {
		return false
	}
	type unwrapList interface{ Unwrap() []error }
	if u, ok := err.(unwrapList); ok {
		for _, e := range u.Unwrap() {
			if !errors.Is(e, errCleanupDegraded) {
				return false
			}
		}
		return true
	}
	// Single-Unwrap wrapper: recurse so a nested join is fully inspected.
	type unwrapSingle interface{ Unwrap() error }
	if u, ok := err.(unwrapSingle); ok {
		return isDegradedOnly(u.Unwrap())
	}
	return true
}

// dirClassifier holds the inputs needed to decide whether each agent directory
// should be removed during cleanup. Built once per cleanup run and queried per directory.
type dirClassifier struct {
	log                  *logger.Logger
	callerProtected      map[string]bool
	marker               *UpdateMarker
	markerErr            error
	requireMarkerDetails bool
	symlinkTarget        string
	symlinkErr           error
	// expiredTTL holds the pre-computed filter result for each parsed TTL.
	// Key present means the directory has a parsed TTL marker. The value is
	// true when the filter said the entry is removable (e.g. expired) and
	// false when the filter said to keep it.
	expiredTTL map[string]bool
}

// shouldRemove returns true when the directory at relPath (relative to topDir) is safe to delete.
// Decision order:
//   - caller-protected: never remove
//   - parsed TTL, unexpired: keep
//   - parsed TTL, expired, live symlink target: keep (defense in depth)
//   - parsed TTL, expired, not symlink target: remove
//   - no TTL, symlink unreadable: keep (cannot verify it isn't live)
//   - no TTL, IS the live symlink target: keep
//   - no TTL, marker unreadable: keep (cannot verify marker doesn't reference it)
//   - no TTL, active marker references it: keep
//   - no TTL, all verification passes: remove (confirmed orphan)
func (dc *dirClassifier) shouldRemove(relPath string) bool {
	if dc.callerProtected[relPath] {
		return false
	}
	if expired, hasTTL := dc.expiredTTL[relPath]; hasTTL {
		if !expired {
			return false
		}
		// Defense in depth: expired TTL but still the live symlink target — keep.
		if dc.symlinkErr == nil && relPath == dc.symlinkTarget {
			dc.log.Debugw("TTL is expired but directory is the live install symlink target; preserving",
				"versionedHome", relPath)
			return false
		}
		return true
	}
	// No TTL entry — treat as orphan candidate; keep unless all verification passes.
	if dc.symlinkErr != nil {
		return false
	}
	if relPath == dc.symlinkTarget {
		return false
	}
	if dc.markerErr != nil {
		return false
	}
	// In strict mode (requireMarkerDetails=true), a nil-Details marker cannot confirm an
	// active upgrade, so it does not protect directories.
	markerProtects := dc.marker != nil && !IsTerminalState(dc.marker) && (!dc.requireMarkerDetails || dc.marker.Details != nil)
	if markerProtects {
		if (dc.marker.VersionedHome != "" && relPath == filepath.Clean(dc.marker.VersionedHome)) ||
			(dc.marker.PrevVersionedHome != "" && relPath == filepath.Clean(dc.marker.PrevVersionedHome)) {
			return false
		}
	}
	return true
}

// cleanupOpts configures optional behaviour of cleanupAgentDirectories.
type cleanupOpts struct {
	// requireMarkerDetails controls whether a marker with nil Details is trusted for directory protection.
	// On disk, Details can be nil for two reasons: (1) marker written by an older agent before the Details field existed, (2) pre-unpack marker written before an upgrade begins.
	// true (strict): used when the upgrade lifecycle is known to have ended. A nil-Details marker carries no information about an active upgrade and does not protect directories.
	// false (lenient): used during periodic cleanup when the upgrade state is unknown. A nil-Details marker may indicate an upgrade in progress, so it still protects referenced directories.
	requireMarkerDetails bool
	// keepLogs skips the "logs" subdirectory when removing a versioned home.
	keepLogs bool
}

// cleanupAgentDirectories removes agent directories that are safe to delete and
// returns the TTL-tracked rollbacks the filter chose to keep.
// If the symlink or upgrade marker could not be read, the returned error wraps
// errCleanupDegraded so callers can react conservatively.
func cleanupAgentDirectories(
	log *logger.Logger,
	topDir string,
	now time.Time,
	source ttl.Source,
	filter RollbackCleanupFilter,
	callerProtected map[string]bool,
	opts cleanupOpts,
) (map[string]ttl.TTLMarker, error) {
	allAgentDirs, err := snapshotAgentDirs(topDir)
	if err != nil {
		return nil, err
	}

	parsedRaw, malformed, err := source.GetAll()
	if err != nil {
		return nil, fmt.Errorf("unable to get available rollbacks: %w", err)
	}
	for versionedHome, parseErr := range malformed {
		log.Infow("TTL marker is unparseable; treating directory as orphan candidate",
			"versionedHome", versionedHome, "error.message", parseErr.Error())
	}

	// Reuse each filter result for both the removal map and the leftover set.
	expiredTTL := make(map[string]bool, len(parsedRaw))
	leftoverRollbacks := make(map[string]ttl.TTLMarker, len(parsedRaw))
	for versionedHome, m := range parsedRaw {
		removable := filter(log, now, versionedHome, m)
		expiredTTL[versionedHome] = removable
		if !removable {
			leftoverRollbacks[versionedHome] = m
		}
	}

	degraded := false

	marker, markerErr := LoadMarker(paths.DataFrom(topDir))
	if markerErr != nil {
		log.Warnw("could not read upgrade marker during cleanup; marker-referenced directories will be kept conservatively",
			"error.message", markerErr.Error())
		marker = nil
		degraded = true
	}

	symlinkTarget, symlinkErr := liveVersionedHome(topDir)
	if symlinkErr != nil {
		log.Warnw("could not resolve live versioned home symlink during cleanup; orphan directories will be kept conservatively",
			"error.message", symlinkErr.Error())
		symlinkTarget = ""
		degraded = true
	}

	dc := &dirClassifier{
		log:                  log,
		callerProtected:      callerProtected,
		marker:               marker,
		markerErr:            markerErr,
		requireMarkerDetails: opts.requireMarkerDetails,
		symlinkTarget:        symlinkTarget,
		symlinkErr:           symlinkErr,
		expiredTTL:           expiredTTL,
	}

	// existingDirSet is built here (rather than in a separate pass) to avoid
	// computing filepath.Rel twice for every directory.
	existingDirSet := make(map[string]bool, len(allAgentDirs))
	var toRemove, keptDirs []string
	for _, absPath := range allAgentDirs {
		relPath, relErr := filepath.Rel(topDir, absPath)
		if relErr != nil {
			log.Debugw("skipping directory with unresolvable relative path",
				"path", absPath, "error.message", relErr.Error())
			continue
		}
		relPath = filepath.Clean(relPath)
		existingDirSet[relPath] = true
		// !opts.keepLogs short-circuits on the common path; preserve this operand order.
		if dc.shouldRemove(relPath) && (!opts.keepLogs || !hasOnlyLogs(log, absPath)) {
			toRemove = append(toRemove, relPath)
		} else {
			keptDirs = append(keptDirs, relPath)
		}
	}

	log.Infow("Starting cleanup of versioned homes", "toKeep", keptDirs, "toRemove", toRemove)

	var aggregateErr error
	for _, relPath := range toRemove {
		hashedDir := filepath.Join(topDir, relPath)
		log.Infow("Removing hashed data directory", "file.path", hashedDir)
		var ignoredDirs []string
		if opts.keepLogs {
			ignoredDirs = []string{"logs"}
		}
		if cleanupErr := install.RemoveBut(log, hashedDir, true, ignoredDirs...); cleanupErr != nil {
			if errors.Is(cleanupErr, os.ErrNotExist) {
				log.Debugw("directory already gone before removal; skipping", "file.path", hashedDir)
				continue
			}
			aggregateErr = errors.Join(aggregateErr, fmt.Errorf("removing %q: %w", hashedDir, cleanupErr))
		}
	}

	// Filter leftoverRollbacks to entries whose directory still exists on disk.
	// In practice this is always identical to leftoverRollbacks (unexpired TTL entries
	// are never put in toRemove), but it defends against external deletions or edge
	// cases where the dir disappears between snapshotAgentDirs and now.
	filteredRollbacks := make(map[string]ttl.TTLMarker, len(leftoverRollbacks))
	for versionedHome, m := range leftoverRollbacks {
		if existingDirSet[filepath.Clean(versionedHome)] {
			filteredRollbacks[versionedHome] = m
		} else {
			log.Debugw("removing stale TTL marker for non-existent directory",
				"versionedHome", versionedHome)
		}
	}

	// Reconcile the on-disk TTL registry when the desired state differs from what was
	// found: expired entries removed, stale entries filtered, or malformed .ttl files
	// present that Set needs to sweep. This also handles .ttl files that survived a
	// partial RemoveBut failure. Skip when the registry is already in the desired
	// state to avoid unnecessary I/O.
	//
	// Concurrency note: a concurrent Upgrade() may write new TTL markers between the
	// GetAll call above and this Set. TTLMarkerRegistry.Set sweeps entries not in the
	// desired map, so a race could briefly remove a newly written marker. This is
	// tolerated: the next cleanup cycle will see it, and the upgrade marker protects
	// the new install's directory independently of the TTL registry.
	if len(filteredRollbacks) != len(parsedRaw) || len(malformed) > 0 {
		if setErr := source.Set(filteredRollbacks); setErr != nil {
			aggregateErr = errors.Join(aggregateErr, fmt.Errorf("syncing TTL registry: %w", setErr))
		}
	}

	switch {
	case degraded && aggregateErr != nil:
		return filteredRollbacks, errors.Join(aggregateErr, errCleanupDegraded)
	case degraded:
		return filteredRollbacks, errCleanupDegraded
	default:
		return filteredRollbacks, aggregateErr
	}
}

// hasOnlyLogs returns true when dir contains exactly one visible (non-hidden) entry
// and that entry is a directory named "logs".
// Hidden entries (names starting with ".") are ignored so that OS artefacts like
// .DS_Store or a leftover .ttl file do not cause a false negative.
func hasOnlyLogs(log *logger.Logger, dir string) bool {
	entries, err := os.ReadDir(dir)
	if err != nil {
		log.Debugw("could not read directory for log-only check; assuming not log-only",
			"file.path", dir, "error.message", err.Error())
		return false
	}
	visibleCount := 0
	logsDir := false
	for _, e := range entries {
		if len(e.Name()) == 0 || e.Name()[0] == '.' {
			continue
		}
		visibleCount++
		if visibleCount > 1 {
			return false
		}
		logsDir = e.IsDir() && e.Name() == "logs"
	}
	return visibleCount == 1 && logsDir
}
