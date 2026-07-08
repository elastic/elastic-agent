// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package upgrade

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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

// cleanupOpts configures optional behaviour of cleanupAgentDirectories.
type cleanupOpts struct {
	// requireMarkerDetails controls whether a marker with nil Details is trusted for directory protection.
	// On disk, Details can be nil for two reasons:
	//   (1) marker written by an older agent before the Details field existed
	//   (2) pre-unpack marker written before an upgrade begins.
	//
	// true (strict): used when the upgrade lifecycle is known to have ended, so we can ignore nil Details
	// false (lenient): used during periodic cleanup when the upgrade state is unknown.
	requireMarkerDetails bool
	// keepLogs skips the "logs" subdirectory when removing a versioned home.
	keepLogs bool
}

// dirClassifier holds the inputs needed to decide whether each agent directory
// should be removed during cleanup. Built once per cleanup run and queried per directory.
type dirClassifier struct {
	log             *logger.Logger
	callerProtected map[string]bool
	marker          *UpdateMarker
	markerErr       error
	// requireMarkerDetails mirrors cleanupOpts.requireMarkerDetails: when true, a marker with nil Details
	// is not trusted to protect directories (strict mode). When false, any non-terminal marker protects them.
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
	var ignoredDirs []string
	if opts.keepLogs {
		ignoredDirs = []string{"logs"}
	}

	for _, relPath := range toRemove {
		hashedDir := filepath.Join(topDir, relPath)
		log.Infow("Removing hashed data directory", "file.path", hashedDir)
		if cleanupErr := install.RemoveBut(log, hashedDir, true, ignoredDirs...); cleanupErr != nil {
			if errors.Is(cleanupErr, os.ErrNotExist) {
				log.Debugw("directory already gone before removal; skipping", "file.path", hashedDir)
				continue
			}
			aggregateErr = errors.Join(aggregateErr, fmt.Errorf("removing %q: %w", hashedDir, cleanupErr))
		}
	}

	// Build the return value: unexpired rollbacks whose directory still exists.
	// In practice always identical to leftoverRollbacks (unexpired entries are never removed),
	// but defends against a directory disappearing between snapshotAgentDirs and now.
	filteredRollbacks := make(map[string]ttl.TTLMarker, len(leftoverRollbacks))
	for versionedHome, m := range leftoverRollbacks {
		if existingDirSet[filepath.Clean(versionedHome)] {
			filteredRollbacks[versionedHome] = m
		}
		// else: directory is gone; the .ttl inside it is gone with it — nothing to remove.
	}

	// Remove .ttl files for malformed entries only. Their directories still exist but the
	// .ttl file cannot be parsed and will never become a valid rollback target.
	// Expired and externally-deleted directories are removed as a whole by RemoveBut above,
	// taking their .ttl with them, so no explicit cleanup is needed for those cases.
	for versionedHome := range malformed {
		if removeErr := source.Remove(versionedHome); removeErr != nil {
			aggregateErr = errors.Join(aggregateErr, fmt.Errorf("removing malformed TTL marker for %q: %w", versionedHome, removeErr))
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
// snapshotAgentDirs returns absolute paths of all elastic-agent-* dirs in the data directory.
// Take the snapshot before reading markers or TTL entries: directories created by a concurrent
// upgrade afterward won't appear and therefore can't be swept by this cleanup run.
func snapshotAgentDirs(topDir string) ([]string, error) {
	entries, err := os.ReadDir(paths.DataFrom(topDir))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("reading data directory: %w", err)
	}
	var dirs []string
	for _, entry := range entries {
		if entry.IsDir() && strings.HasPrefix(entry.Name(), "elastic-agent-") {
			dirs = append(dirs, filepath.Join(paths.DataFrom(topDir), entry.Name()))
		}
	}
	return dirs, nil
}

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
