// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build !windows

package cmd

import (
	"fmt"
	"os"
	"syscall"

	"github.com/elastic/elastic-agent/pkg/core/logger"
)

func takedownWatcher(log *logger.Logger, pidFetchFunc watcherPIDsFetcher) error {
	pids, err := pidFetchFunc()
	if err != nil {
		return fmt.Errorf("error listing watcher processes: %s", err)
	}

	ownPID := os.Getpid()

	for _, pid := range pids {

		if pid == ownPID {
			continue
		}

		log.Debugf("attempting to terminate watcher process with PID: %d", pid)

		process, err := os.FindProcess(pid)
		if err != nil {
			log.Errorf("error finding watcher process with PID: %d: %s", pid, err)
			continue
		}

		err = process.Signal(syscall.SIGTERM)
		if err != nil {
			log.Errorf("error killing watcher process with PID: %d: %s", pid, err)
			continue
		}

	}
	return nil
}
