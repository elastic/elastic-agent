// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package upgrade

import (
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/ttl"
	"github.com/elastic/elastic-agent/internal/pkg/agent/install"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

// errCleanupDegraded signals that cleanupAgentDirectories completed but with
// degraded verification (symlink and/or upgrade marker could not be read).
// The scheduler's fast-retry logic detects it via errors.Is. The message text
// is part of the contract: SRE alerting and dashboards may key on it.
var errCleanupDegraded = errors.New("rollback cleanup completed with degraded verification")

// dirClassifier holds the inputs needed to classify each agent directory during
// cleanup. It is built once per cleanup run by cleanupAgentDirectories and
// then queried per directory via shouldRemove. Splitting the classifier into
// a method on this struct lets the 9-row decision matrix be unit-tested
// directly without a filesystem fixture.
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

// shouldRemove returns true when the directory at relPath (relative to topDir)
// is safe to delete. The decision follows a 9-row matrix:
//
//  1. caller-protected wins everything (current install, rollback target, ...)
//  2. parsed TTL says keep (unexpired) -> keep
//  3. parsed TTL says remove, but it's the live symlink target -> keep (defense in depth)
//  4. parsed TTL says remove, and not the live symlink target -> remove
//  5. no parsed TTL, symlink unreadable -> keep (cannot verify it isn't live)
//  6. no parsed TTL, IS the live symlink target -> keep
//  7. no parsed TTL, marker unreadable -> keep (cannot verify marker doesn't reference)
//  8. no parsed TTL, active marker references it -> keep
//  9. no parsed TTL, all verification passes -> remove (confirmed orphan)
func (dc *dirClassifier) shouldRemove(relPath string) bool {
	// Row 1: caller-protected wins everything.
	if dc.callerProtected[relPath] {
		return false
	}
	// Rows 2-4: parsed TTL.
	if expired, hasTTL := dc.expiredTTL[relPath]; hasTTL {
		if !expired {
			return false // row 2: unexpired
		}
		// Row 3: expired but the live symlink target. Defense in depth.
		if dc.symlinkErr == nil && relPath == dc.symlinkTarget {
			dc.log.Warnw("TTL is expired but directory is the live install symlink target; preserving",
				"versionedHome", relPath)
			return false
		}
		return true // row 4
	}
	// Rows 5-9: no parsed TTL. Orphan candidate.
	if dc.symlinkErr != nil {
		return false // row 5
	}
	if relPath == dc.symlinkTarget {
		return false // row 6
	}
	if dc.markerErr != nil {
		return false // row 7
	}
	if dc.marker != nil && !IsTerminalState(dc.marker) && (!dc.requireMarkerDetails || dc.marker.Details != nil) {
		if relPath == filepath.Clean(dc.marker.VersionedHome) || relPath == filepath.Clean(dc.marker.PrevVersionedHome) {
			return false // row 8
		}
	}
	return true // row 9
}

// cleanupAgentDirectories is the unified core of post-upgrade and periodic
// rollback cleanup. It snapshots agent dirs, reads TTL markers, the upgrade
// marker and the live install symlink, classifies each directory via
// shouldRemove and sweeps the ones the classifier marks for removal.
//
// Returns the set of TTL-tracked rollbacks the filter chose to keep (so the
// scheduler can pick the next wake-up time) and an aggregate error. If
// verification was degraded (symlink and/or marker unreadable) the returned
// error wraps errCleanupDegraded so callers can react conservatively.
func cleanupAgentDirectories(
	log *logger.Logger,
	topDir string,
	now time.Time,
	source ttl.Source,
	filter RollbackCleanupFilter,
	callerProtected map[string]bool,
	requireMarkerDetails bool,
	keepLogs bool,
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
		log.Infow("TTL marker is unparseable; directory will not be protected from cleanup",
			"versionedHome", versionedHome, "error.message", parseErr.Error())
	}

	// Single pass over parsed TTL markers: call the filter exactly once per
	// entry, producing both the expiredTTL lookup used by shouldRemove and
	// the leftoverRollbacks map returned to the scheduler. Calling the
	// filter twice would cause CleanupExpiredRollbacks to log "expired,
	// removing directory" twice per cleanup run.
	expiredTTL := make(map[string]bool, len(parsedRaw))
	leftoverRollbacks := make(map[string]ttl.TTLMarker)
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
		requireMarkerDetails: requireMarkerDetails,
		symlinkTarget:        symlinkTarget,
		symlinkErr:           symlinkErr,
		expiredTTL:           expiredTTL,
	}

	var toRemove, keptDirs []string
	for _, absPath := range allAgentDirs {
		relPath, relErr := filepath.Rel(topDir, absPath)
		if relErr != nil {
			log.Debugw("skipping directory with unresolvable relative path",
				"path", absPath, "error.message", relErr.Error())
			continue
		}
		relPath = filepath.Clean(relPath)
		if dc.shouldRemove(relPath) {
			toRemove = append(toRemove, relPath)
		} else {
			keptDirs = append(keptDirs, relPath)
		}
	}

	log.Infof("Starting cleanup of versioned homes. Keeping: %v", keptDirs)

	keepDirsMap := make(map[string]bool, len(keptDirs))
	for _, d := range keptDirs {
		keepDirsMap[d] = true
	}
	log.Debugw("preparing to cleanup agent directories", "keep_dirs", keepDirsMap, "to_remove", len(toRemove))

	for _, d := range keptDirs {
		log.Debugw("leaving agent directory intact", "path", d)
	}

	var aggregateErr error
	for _, relPath := range toRemove {
		hashedDir := filepath.Join(topDir, relPath)
		// Unified per-removal log line for both callers (post-upgrade and
		// periodic cleanup). The previous periodic-only string
		// "removing agent directory" is intentionally gone; SRE alerts that
		// keyed on either string should key on "Removing hashed data directory".
		log.Infow("Removing hashed data directory", "file.path", hashedDir)
		var ignoredDirs []string
		if keepLogs {
			ignoredDirs = []string{"logs"}
		}
		if cleanupErr := install.RemoveBut(log, hashedDir, true, ignoredDirs...); cleanupErr != nil {
			aggregateErr = errors.Join(aggregateErr, cleanupErr)
		}
	}

	switch {
	case degraded && aggregateErr != nil:
		return leftoverRollbacks, errors.Join(aggregateErr, errCleanupDegraded)
	case degraded:
		return leftoverRollbacks, errCleanupDegraded
	default:
		return leftoverRollbacks, aggregateErr
	}
}
