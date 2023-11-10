// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build windows

package upgrade

import (
	"os"
	"time"
)

const markerAccessTimeout = 10 * time.Second

// On Windows, readMarkerFile tries to read the marker file, retrying with
// randomized exponential backoff up to markerAccessTimeout duration. This retry
// mechanism is necessary since the marker file could be accessed by multiple
// processes (the Upgrade Watcher and the main Agent process) at the same time,
// which could fail on Windows.
func readMarkerFile(markerFile string) ([]byte, error) {
	// TODO: use github.com/cenkalti/backoff
	return os.ReadFile(markerFile)
}

// On Windows, writeMarkerFile tries to write the marker file, retrying with
// randomized exponential backoff up to markerAccessTimeout duration. This retry
// mechanism is necessary since the marker file could be accessed by multiple
// processes (the Upgrade Watcher and the main Agent process) at the same time,
// which could fail on Windows.
func writeMarkerFile(markerFile string, markerBytes []byte) error {
	// TODO: use github.com/cenkalti/backoff
	return os.WriteFile(markerFilePath(), markerBytes, 0600)
}
