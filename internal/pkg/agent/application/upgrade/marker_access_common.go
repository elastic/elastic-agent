// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package upgrade

import (
	"fmt"
	"os"
)

func writeMarkerFileCommon(markerFile string, markerBytes []byte, shouldFsync bool) error {
	f, err := os.OpenFile(markerFile, os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		return fmt.Errorf("failed to open upgrade marker file for writing: %w", err)
	}
	defer f.Close()

	if _, err := f.Write(markerBytes); err != nil {
		return fmt.Errorf("failed to write upgrade marker file: %w", err)
	}

	if !shouldFsync {
		return nil
	}

	if err := f.Sync(); err != nil {
		return fmt.Errorf("failed to sync upgrade marker file to disk: %w", err)
	}

	return nil
}
