// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build linux

package upgrade

import (
	"fmt"
	"os"
	"syscall"
)

func getAvailableDiskSpaceAt(dir string) (uint64, error) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(dir, &stat); err != nil {
		return 0, err
	}
	if stat.Bsize < 0 {
		return 0, fmt.Errorf("filesystem block size is negative")
	}
	return stat.Bavail * uint64(stat.Bsize), nil
}

func getVolumeNameAt(dir string) (string, error) {
	info, err := os.Stat(dir)
	if err != nil {
		return "", err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return "", fmt.Errorf("could not determine filesystem for %s", dir)
	}
	return fmt.Sprint(stat.Dev), nil
}
