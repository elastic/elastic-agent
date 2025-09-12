// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build !windows

package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"syscall"

	"github.com/elastic/elastic-agent/pkg/core/logger"
)

func takedownWatcher(ctx context.Context, log *logger.Logger, pidFetchFunc watcherPIDsFetcher) error {
	pids, err := pidFetchFunc()
	if err != nil {
		return fmt.Errorf("error listing watcher processes: %w", err)
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
			accumulatedSignalingErrors = errors.Join(accumulatedSignalingErrors, fmt.Errorf("error finding watcher process with PID: %d: %w", pid, err))
			continue
		}

		err = process.Signal(syscall.SIGTERM)
		if err != nil {
			accumulatedSignalingErrors = errors.Join(accumulatedSignalingErrors, fmt.Errorf("error killing watcher process with PID: %d: %w", pid, err))
			continue
		}

	}
	return accumulatedSignalingErrors
}

func isProcessLive(process *os.Process) (bool, error) {
	signalErr := process.Signal(syscall.Signal(0))
	if signalErr != nil {
		return false, nil //nolint:nilerr // if we receive an error it means that the process is not running, so the check completed without errors
	} else {
		return true, nil
	}
}
