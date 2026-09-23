// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build darwin

package upgrade

import (
	"fmt"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

func preallocateFile(file *os.File, size int64) error {
	if size <= 0 {
		return nil
	}

	var st unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &st); err != nil {
		return err
	}
	allocated := st.Blocks * 512
	if allocated >= size {
		return nil
	}

	store := unix.Fstore_t{
		Flags:   unix.F_ALLOCATECONTIG | unix.F_ALLOCATEALL,
		Posmode: unix.F_PEOFPOSMODE,
		Length:  size - allocated,
	}
	if err := unix.FcntlFstore(file.Fd(), unix.F_PREALLOCATE, &store); err != nil {
		store.Flags = unix.F_ALLOCATEALL
		if err := unix.FcntlFstore(file.Fd(), unix.F_PREALLOCATE, &store); err != nil {
			return err
		}
	}
	return nil
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
