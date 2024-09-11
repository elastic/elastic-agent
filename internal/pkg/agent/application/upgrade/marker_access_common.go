// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package upgrade

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/elastic/elastic-agent-libs/file"
)

func writeMarkerFileCommon(markerFile string, markerBytes []byte, shouldFsync bool) error {
	f, err := os.CreateTemp(
		filepath.Dir(markerFile), fmt.Sprintf("%d-*.tmp", os.Getpid()))
	if err != nil {
		return fmt.Errorf("failed to open upgrade marker file for writing: %w", err)
	}
	once := sync.Once{}
	closeFile := func() {
		once.Do(func() {
			f.Close()
		})
	}
	defer closeFile()

	if _, err := f.Write(markerBytes); err != nil {
		return fmt.Errorf("failed to write upgrade marker file: %w", err)
	}

	if !shouldFsync {
		return nil
	}

	if err := f.Sync(); err != nil {
		return fmt.Errorf("failed to sync upgrade marker file to disk: %w", err)
	}
	// I think we need to close before trying to swap the files on Windows
	closeFile()

	if err := file.SafeFileRotate(markerFile, f.Name()); err != nil {
		return fmt.Errorf("failed to safe rotate upgrade marker file: %w", err)
	}

	return nil
}
