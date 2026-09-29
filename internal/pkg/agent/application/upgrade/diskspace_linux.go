// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build linux

package upgrade

import (
	"fmt"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

const (
	FallbackArchiveSize = uint64(700 * 1024 * 1024)
	FallbackPayloadSize = uint64(2 * 1024 * 1024 * 1024)

	fsNoCompFl = 0x00000400
	fsNoCowFl  = 0x00800000
)

func disableCompression(file *os.File) {
	fd := int(file.Fd())
	flags, err := unix.IoctlGetInt(fd, unix.FS_IOC_GETFLAGS)
	if err != nil {
		return
	}
	_ = unix.IoctlSetPointerInt(fd, unix.FS_IOC_SETFLAGS, flags|fsNoCompFl|fsNoCowFl)
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
