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
// Callers detect it via errors.Is.
var errCleanupDegraded = errors.New("rollback cleanup completed with degraded verification")

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
			dc.log.Warnw("TTL is expired but directory is the live install symlink target; preserving",
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
	// In strict mode (requireMarkerDetails=true), a marker with nil Details cannot confirm an active upgrade, so it does not protect directories.
	if dc.marker != nil && !IsTerminalState(dc.marker) && (!dc.requireMarkerDetails || dc.marker.Details != nil) {
		if relPath == filepath.Clean(dc.marker.VersionedHome) || relPath == filepath.Clean(dc.marker.PrevVersionedHome) {
			return false
		}
	}
	return true
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

	// Reuse each filter result for both the removal map and the leftover set.
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
