// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build !windows

package upgrade

import (
	"fmt"
	"os"
	"syscall"
)

const openNoFollow = syscall.O_NOFOLLOW

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
