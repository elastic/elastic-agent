// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build !windows

package upgrade

import (
	"io/ioutil"
)

// On non-Windows platforms, readMarkerFile simply reads the marker file.
// See marker_access_windows.go for behavior on Windows platforms.
func readMarkerFile(markerFile string) ([]byte, error) {
	return ioutil.ReadFile(markerFile)
}

// On non-Windows platforms, writeMarkerFile simply writes the marker file.
// See marker_access_windows.go for behavior on Windows platforms.
func writeMarkerFile(markerFile string, markerBytes []byte) error {
	return ioutil.WriteFile(markerFilePath(), markerBytes, 0600)
}
