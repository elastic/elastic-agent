// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package ttl

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v2"

	"github.com/elastic/elastic-agent/pkg/core/logger"
)

const ttlMarkerName = ".ttl"

var defaultMarkerGlobPattern = filepath.Join("data", "elastic-agent-*", ttlMarkerName)

type TTLMarkerRegistry struct {
	baseDir               string
	markerFileGlobPattern string
	log                   *logger.Logger
}

func NewTTLMarkerRegistry(log *logger.Logger, baseDir string) *TTLMarkerRegistry {
	return &TTLMarkerRegistry{
		baseDir:               baseDir,
		markerFileGlobPattern: defaultMarkerGlobPattern,
		log:                   log,
	}
}

// Set reconciles the on-disk .ttl markers with the desired state m: existing
// markers whose versionedHome is not in m are removed, and entries in m are
// written (creating or overwriting). Existing markers with unparseable payloads
// are tolerated via GetAll's partial-success contract: malformed entries are
// logged and either swept (when absent from m) or overwritten by addOrReplace
// (when present in m), so a single corrupt marker cannot wedge upgrades or
// rollbacks.
func (T TTLMarkerRegistry) Set(m map[string]TTLMarker) error {
	existingMarkers, malformed, err := T.GetAll()
	if err != nil {
		return fmt.Errorf("accessing existing markers: %w", err)
	}

	for versionedHome := range existingMarkers {
		if _, ok := m[versionedHome]; ok {
			continue
		}
		T.log.Infof("Removing TTL marker for %s: not in new desired state", versionedHome)
		err = os.Remove(filepath.Join(T.baseDir, versionedHome, ttlMarkerName))
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("removing ttl marker for %q: %w", versionedHome, err)
		}
	}

	for versionedHome, parseErr := range malformed {
		if _, ok := m[versionedHome]; ok {
			T.log.Infow("Overwriting malformed TTL marker with valid entry",
				"versionedHome", versionedHome, "error.message", parseErr.Error())
			continue
		}
		T.log.Infow("Sweeping malformed TTL marker: not in new desired state",
			"versionedHome", versionedHome, "error.message", parseErr.Error())
		err = os.Remove(filepath.Join(T.baseDir, versionedHome, ttlMarkerName))
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("removing ttl marker for %q: %w", versionedHome, err)
		}
	}

	return T.addOrReplace(m)
}

func (T TTLMarkerRegistry) Remove(versionedHome string) error {
	err := os.Remove(filepath.Join(T.baseDir, versionedHome, ttlMarkerName))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("removing ttl marker for %q: %w", versionedHome, err)
	}
	if err == nil {
		T.log.Debugf("Removing marker for versionedHome: %s", versionedHome)
	}
	return nil
}

// GetAll reads all .ttl markers under the registry's base directory and
// returns two maps:
//   - markers: successfully parsed entries keyed by versioned home (relative
//     to baseDir).
//   - malformed: per-entry errors keyed by versioned home for entries whose
//     .ttl file could not be read or parsed (e.g. corrupt YAML, permissions,
//     ENOENT during read). Entries whose path cannot be made relative to
//     baseDir are silently skipped (unreachable in practice — see inline comment).
//
// The returned error is non-nil only on structural failures (e.g. a glob
// failure) where no scan could be performed. Callers that need to be
// conservative about disk-state decisions (e.g. cleanup keep lists) should
// inspect malformed and decide whether to preserve those directories rather
// than discarding them as untracked.
func (T TTLMarkerRegistry) GetAll() (map[string]TTLMarker, map[string]error, error) {
	matches, err := filepath.Glob(filepath.Join(T.baseDir, T.markerFileGlobPattern))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to glob files using %q: %w", T.markerFileGlobPattern, err)
	}
	T.log.Debugf("Found matching versionedHomes: %v", matches)
	ttlMarkers := make(map[string]TTLMarker, len(matches))
	malformed := map[string]error{}
	for _, match := range matches {
		T.log.Debugf("Reading marker from versionedHome: %s", match)
		// relErr is unreachable in practice: every match is produced by a glob
		// rooted at T.baseDir, so filepath.Dir(match) is always under T.baseDir
		// and filepath.Rel cannot fail. The branch is kept as a defensive guard.
		relPath, relErr := filepath.Rel(T.baseDir, filepath.Dir(match))
		if relErr != nil {
			T.log.Infof("skipping marker %q: failed to compute path relative to %q: %s", match, T.baseDir, relErr)
			continue
		}
		marker, readErr := readTTLMarker(match)
		if readErr != nil {
			T.log.Infof("skipping malformed marker %q: %s", match, readErr)
			malformed[relPath] = fmt.Errorf("reading marker file %q: %w", match, readErr)
			continue
		}
		ttlMarkers[relPath] = marker
	}

	return ttlMarkers, malformed, nil
}

func (T TTLMarkerRegistry) addOrReplace(m map[string]TTLMarker) error {
	for versionedHome, marker := range m {
		dstFilePath := filepath.Join(T.baseDir, versionedHome, ttlMarkerName)
		err := writeTTLMarker(dstFilePath, marker)
		if err != nil {
			return fmt.Errorf("writing marker %q: %w", dstFilePath, err)
		}
	}

	return nil
}

func readTTLMarker(filePath string) (TTLMarker, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return TTLMarker{}, fmt.Errorf("failed to open %q: %w", filePath, err)
	}
	defer func(file *os.File) {
		_ = file.Close()
	}(file)
	ttlMarker := TTLMarker{}
	err = yaml.NewDecoder(file).Decode(&ttlMarker)
	if err != nil {
		return TTLMarker{}, fmt.Errorf("failed to decode %q: %w", filePath, err)
	}

	return ttlMarker, nil
}

func writeTTLMarker(filePath string, marker TTLMarker) error {
	file, err := os.OpenFile(filePath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0660)
	if err != nil {
		return fmt.Errorf("failed to open %q: %w", filePath, err)
	}
	defer func(file *os.File) {
		_ = file.Close()
	}(file)

	err = yaml.NewEncoder(file).Encode(marker)
	if err != nil {
		return fmt.Errorf("failed to encode %q: %w", filePath, err)
	}

	return nil
}
