// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build windows

package reexec

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

// exec performs execution on Windows.
//
// Windows does not support the ability to execute over the same PID and memory. Depending on the execution context
// different scenarios need to occur.
//
//   - Services.msc - A new child process is spawned that waits for the service to stop, then restarts it and the
//     current process just exits.
//
// * Sub-process - As a sub-process a new child is spawned and the current process just exits.
func reexec(log *logger.Logger, executable string, argOverrides ...string) error {
	if info.RunningUnderSupervisor() {
		// running as a service; spawn re-exec windows sub-process
		log.Infof("Running as Windows service; triggering service restart")
		args := []string{filepath.Base(executable), "reexec_windows", paths.ServiceName, strconv.Itoa(os.Getpid())}
		args = append(args, argOverrides...)
		cmd := exec.Cmd{
			Path:   executable,
			Args:   args,
			Stdin:  os.Stdin,
			Stdout: os.Stdout,
			Stderr: os.Stderr,
		}
		if err := cmd.Start(); err != nil {
			return err
		}
	} else {
		// running as a sub-process of another process; just execute as a child
		log.Infof("Running as Windows process; spawning new child process")
		args := []string{filepath.Base(executable)}
		args = append(args, os.Args[1:]...)
		args = append(args, argOverrides...)
		cmd := exec.Cmd{
			Path:   executable,
			Args:   args,
			Stdin:  os.Stdin,
			Stdout: os.Stdout,
			Stderr: os.Stderr,
		}
		if err := cmd.Start(); err != nil {
			return err
		}
	}
	// force log sync before exit
	_ = log.Sync()
	return nil
}
