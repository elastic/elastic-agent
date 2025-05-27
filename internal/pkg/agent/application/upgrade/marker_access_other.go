// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build !windows

package upgrade

import (
	"fmt"
	"os"

	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
)

// On non-Windows platforms, readMarkerFile simply reads the marker file.
// See marker_access_windows.go for behavior on Windows platforms.
func readMarkerFile(markerFile string) ([]byte, error) {
	fileLock, err := lockMarkerFile(markerFile)
	if err != nil {
		return nil, fmt.Errorf("locking update marker file %q for reading: %w", markerFile, err)
	}
	defer fileLock.Unlock()
	markerFileBytes, err := os.ReadFile(markerFile)
	if errors.Is(err, os.ErrNotExist) {
		// marker doesn't exist, nothing to do
		return nil, nil
	}
	return markerFileBytes, nil
}

// On non-Windows platforms, writeMarkerFile simply writes the marker file.
// See marker_access_windows.go for behavior on Windows platforms.
func writeMarkerFile(markerFile string, markerBytes []byte, shouldFsync bool) error {
	fileLock, err := lockMarkerFile(markerFile)
	if err != nil {
		return fmt.Errorf("locking update marker file %q for writing: %w", markerFile, err)
	}
	defer fileLock.Unlock()
	return writeMarkerFileCommon(markerFile, markerBytes, shouldFsync)
}
