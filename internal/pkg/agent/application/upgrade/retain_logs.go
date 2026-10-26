// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package upgrade

import (
	"fmt"
	"path/filepath"
	"time"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/ttl"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

// retainedHome returns the versioned home, relative to the top path, of the version a failed upgrade was
// upgrading to, as recorded in the upgrade marker. Its logs are retained after the rollback.
// It returns "" if there is nothing to retain: the marker has no failed home, or it is the home we roll back to.
func retainedHome(marker *UpdateMarker) string {
	if marker == nil {
		return ""
	}
	home := marker.VersionedHome
	if home == "" && len(marker.Hash) >= HashLen {
		// the marker may have been written by an older agent where the versioned home is always data/elastic-agent-<shortHash>
		home = filepath.Join("data", fmt.Sprintf("%s-%s", AgentName, marker.Hash[:HashLen]))
	}
	if home == "" {
		return ""
	}
	home = filepath.Clean(home)
	if home == filepath.Clean(marker.PrevVersionedHome) {
		return ""
	}
	return home
}

// retainFailedUpgradeLogs writes a TTL marker flagged RetentionOnly, valid for the given retention, into the
// failed home (see retainedHome). Cleanups keep homes with an unexpired TTL marker, so the home survives the cleanup
// that the agent we roll back to runs when it starts. It must be called before that agent is restarted.
// Existing TTL markers are not touched.
func retainFailedUpgradeLogs(log *logger.Logger, topDir, failedHome string, failedUpgrade *UpdateMarker, retention time.Duration) error {
	err := ttl.NewTTLMarkerRegistry(log, topDir).Add(failedHome, ttl.TTLMarker{
		Version:       failedUpgrade.Version,
		Hash:          failedUpgrade.Hash,
		ValidUntil:    time.Now().Add(retention),
		RetentionOnly: true,
	})
	if err != nil {
		return fmt.Errorf("writing retention TTL marker for %q: %w", failedHome, err)
	}
	return nil
}
