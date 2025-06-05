// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build !windows

package upgrade

import (
	"errors"
	"fmt"
	"os"
)

// On non-Windows platforms, readMarkerFile simply reads the marker file.
// See marker_access_windows.go for behavior on Windows platforms.
func readMarkerFile(markerFile string) (bytes []byte, err error) {
	fileLock, err := lockMarkerFile(markerFile)
	if err != nil {
		return nil, fmt.Errorf("locking update marker file %q for reading: %w", markerFile, err)
	}
	defer func(fileLock Locker) {
		errUnlock := fileLock.Unlock()
		if errUnlock != nil {
			err = errors.Join(err, fmt.Errorf("unlocking marker file after reading: %w", errUnlock))
		}
	}(fileLock)
	markerFileBytes, err := os.ReadFile(markerFile)
	if errors.Is(err, os.ErrNotExist) {
		// marker doesn't exist, nothing to do
		return nil, nil
	}
	return markerFileBytes, nil
}

// On non-Windows platforms, writeMarkerFile simply writes the marker file.
// See marker_access_windows.go for behavior on Windows platforms.
func writeMarkerFile(markerFile string, markerBytes []byte, shouldFsync bool) (err error) {
	fileLock, err := lockMarkerFile(markerFile)
	if err != nil {
		return fmt.Errorf("locking update marker file %q for writing: %w", markerFile, err)
	}
	defer func(fileLock Locker) {
		errUnlock := fileLock.Unlock()
		if errUnlock != nil {
			err = errors.Join(err, fmt.Errorf("unlocking marker file after writing: %w", errUnlock))
		}
	}(fileLock)
	return writeMarkerFileCommon(markerFile, markerBytes, shouldFsync)
}
