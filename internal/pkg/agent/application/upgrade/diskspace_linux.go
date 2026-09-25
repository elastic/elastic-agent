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

func preallocateFile(file *os.File, size int64) error {
	if size > 0 {
		var err error
		for {
			err = unix.Fallocate(int(file.Fd()), 0, 0, size)
			if err != unix.EINTR {
				break
			}
		}
		if err == unix.EOPNOTSUPP || err == unix.ENOSYS {
			return preallocateFileFallback(file, size)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// Fallback method for when Fallocate isn't supported.
// Modelled after the glibc implementation.
func preallocateFileFallback(file *os.File, size int64) error {
	info, err := file.Stat()
	if err != nil {
		return err
	}
	var stat unix.Statfs_t
	if err := unix.Fstatfs(int(file.Fd()), &stat); err != nil {
		return err
	}
	blockSize := stat.Bsize
	if blockSize <= 0 {
		blockSize = 512
	}
	// cap as block size on network filesystems can be misleading
	blockSize = min(blockSize, 4096)

	// touch one byte per block
	var b [1]byte
	for offset := int64(0); offset < size; {
		offset += min(blockSize, size-offset)
		b[0] = 0
		if offset <= info.Size() {
			if _, err := file.ReadAt(b[:], offset-1); err != nil {
				return err
			}
			if b[0] != 0 {
				continue
			}
		}
		if _, err := file.WriteAt(b[:], offset-1); err != nil {
			return err
		}
	}
	return file.Sync()
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
