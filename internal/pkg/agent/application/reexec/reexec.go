// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build !windows

package reexec

import (
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"

	"github.com/elastic/elastic-agent/pkg/core/logger"
)

func reexec(log *logger.Logger, executable string, argOverrides ...string) error {
	// force log sync, before re-exec
	_ = log.Sync()

	args := []string{filepath.Base(executable)}
	args = append(args, os.Args[1:]...)
	args = append(args, argOverrides...)
	return unix.Exec(executable, args, os.Environ())
}
