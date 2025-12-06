// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package ttl

import (
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

func (T TTLMarkerRegistry) Set(m map[string]TTLMarker) error {
	// identify the marker files to be deleted first
	existingMarkers, err := T.Get()
	if err != nil {
		return fmt.Errorf("accessing existing markers: %w", err)
	}

	for versionedHome := range existingMarkers {
		_, ok := m[versionedHome]
		if !ok {
			// the existing marker should not be in the final state
			T.log.Debugf("Removing marker for versionedHome: %s", versionedHome)
			err = os.Remove(filepath.Join(T.baseDir, versionedHome, ttlMarkerName))
			if err != nil {
				return fmt.Errorf("removing ttl marker for %q: %w", versionedHome, err)
			}
		}
	}

	// create all the remaining markers
	return T.addOrReplace(m)
}

func (T TTLMarkerRegistry) Get() (map[string]TTLMarker, error) {
	matches, err := filepath.Glob(filepath.Join(T.baseDir, T.markerFileGlobPattern))
	if err != nil {
		return nil, fmt.Errorf("failed to glob files using %q: %w", T.markerFileGlobPattern, err)
	}
	T.log.Debugf("Found matching versionedHomes: %v", matches)
	ttlMarkers := make(map[string]TTLMarker, len(matches))
	for _, match := range matches {
		T.log.Debugf("Reading marker from versionedHome: %s", match)
		relPath, err := filepath.Rel(T.baseDir, filepath.Dir(match))
		if err != nil {
			return nil, fmt.Errorf("failed to determine path for %q relative to %q : %w", match, T.baseDir, err)
		}
		marker, err := readTTLMarker(match)
		if err != nil {
			return nil, fmt.Errorf("failed to read marker from file %q: %w", match, err)
		}
		ttlMarkers[relPath] = marker
	}

	return ttlMarkers, nil
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
	file, err := os.Create(filePath)
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
