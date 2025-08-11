// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build !windows

package upgrade

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"syscall"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

func createTakeDownWatcherCommand(ctx context.Context) *exec.Cmd {
	executable, _ := os.Executable()

	// #nosec G204 -- user cannot inject any parameters to this command
	cmd := exec.CommandContext(ctx, executable, watcherSubcommand,
		"--path.config", paths.Config(),
		"--path.home", paths.Top(),
		"--takedown",
	)
	return cmd
}

func takedownWatcher(ctx context.Context, log *logger.Logger, pidFetchFunc watcherPIDsFetcher) error {
	pids, err := pidFetchFunc()
	if err != nil {
		return fmt.Errorf("error listing watcher processes: %s", err)
	}

	ownPID := os.Getpid()
	var accumulatedSignalingErrors error
	for _, pid := range pids {

		if ctx.Err() != nil {
			return ctx.Err()
		}

		if pid == ownPID {
			continue
		}

		log.Debugf("attempting to terminate watcher process with PID: %d", pid)

		process, err := os.FindProcess(pid)
		if err != nil {
			accumulatedSignalingErrors = errors.Join(accumulatedSignalingErrors, fmt.Errorf("error finding watcher process with PID: %d: %s", pid, err))
			continue
		}

		err = process.Signal(syscall.SIGTERM)
		if err != nil {
			accumulatedSignalingErrors = errors.Join(accumulatedSignalingErrors, fmt.Errorf("error killing watcher process with PID: %d: %s", pid, err))
			continue
		}

	}
	return accumulatedSignalingErrors
}
