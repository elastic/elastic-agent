// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build linux || windows

package vault

import (
	"fmt"
	"os"
	"path/filepath"
)

// writeFile "atomic" file write, utilizes temp file and replace
// os.CreateTemp creates the file with 0600 mask, which is what we need
func writeFile(fp string, data []byte) (err error) {
	dir, fn := filepath.Split(fp)
	if dir == "" {
		dir = "."
	}

	f, err := os.CreateTemp(dir, fn)
	if err != nil {
		return fmt.Errorf("failed creating temp file: %w", err)
	}
	defer func() {
		if err != nil {
			_ = os.Remove(f.Name())
		}
	}()
	defer f.Close()

	_, err = f.Write(data)
	if err != nil {
		return fmt.Errorf("failed writing temp file: %w", err)
	}

	err = f.Sync()
	if err != nil {
		return fmt.Errorf("failed syncing temp file: %w", err)
	}

	err = f.Close()
	if err != nil {
		return fmt.Errorf("failed closing temp file: %w", err)
	}

	return os.Rename(f.Name(), fp)
}
