// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build !windows

package upgrade

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/elastic/elastic-agent/pkg/core/logger"
)

func StartWatcherCmd(log *logger.Logger, createCmd cmdFactory, opts ...WatcherInvocationOpt) (*exec.Cmd, error) {

	invocationOpts := applyWatcherInvocationOpts(opts...)

	cmd := createCmd()
	log.Infow("Starting upgrade watcher", "path", cmd.Path, "args", cmd.Args, "env", cmd.Env, "dir", cmd.Dir)
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start Upgrade Watcher: %w", err)
	}

	upgradeWatcherPID := cmd.Process.Pid
	agentPID := os.Getpid()

	go func() {
		if err := cmd.Wait(); err != nil {
			log.Infow("Upgrade Watcher exited with error", "agent.upgrade.watcher.process.pid", agentPID, "agent.process.pid", upgradeWatcherPID, "error.message", err)
		}
		if invocationOpts.postWatchHook != nil {
			invocationOpts.postWatchHook()
		}
	}()
	return cmd, nil
}
