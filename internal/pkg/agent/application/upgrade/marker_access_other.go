// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build !windows

package upgrade

import (
	"os"

	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
)

// On non-Windows platforms, readMarkerFile simply reads the marker file.
// See marker_access_windows.go for behavior on Windows platforms.
func readMarkerFile(markerFile string) ([]byte, error) {
	markerFileBytes, err := os.ReadFile(markerFile)
	if errors.Is(err, os.ErrNotExist) {
		// marker doesn't exist, nothing to do
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return markerFileBytes, nil
}

// On non-Windows platforms, writeMarkerFile simply writes the marker file.
// See marker_access_windows.go for behavior on Windows platforms.
func writeMarkerFile(markerFile string, markerBytes []byte, shouldFsync bool) error {
	return writeMarkerFileCommon(markerFile, markerBytes, shouldFsync)
}

// On non-Windows platforms, removeMarkerFile simply removes the marker file.
// See marker_access_windows.go for behavior on Windows platforms.
// Unlike the Windows version, this may return os.ErrNotExist; callers must
// handle it (the Windows version swallows it).
func removeMarkerFile(markerFile string) error {
	return os.Remove(markerFile)
}
