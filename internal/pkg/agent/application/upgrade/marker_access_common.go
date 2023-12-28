// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package upgrade

import (
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/elastic/elastic-agent-libs/file"
)

func writeMarkerFileCommon(markerFile string, markerBytes []byte, shouldFsync bool) error {
	tmpMarkerFile := fmt.Sprintf("%s-%d-%d.tmp", markerFile, os.Getpid(), time.Now().UnixMilli())

	f, err := os.OpenFile(tmpMarkerFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
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

	if err := file.SafeFileRotate(markerFile, tmpMarkerFile); err != nil {
		return fmt.Errorf("failed to safe rotate upgrade marker file: %w", err)
	}

	return nil
}
