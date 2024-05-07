// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package upgradetest

import (
	"context"
	"fmt"
	"os"
	"time"

	atesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/utils"
)

// FastWatcherCfg is configuration that makes the watcher run faster.
const FastWatcherCfg = `
agent.upgrade.watcher:
  grace_period: 1m
  error_check.interval: 15s
  crash_check.interval: 15s
`

// ConfigureFastWatcher writes an Elastic Agent configuration that
// adjusts the watcher to be faster.
//
// Note: Not all versions or modes of the Elastic Agent respect this option
// that is why the `WaitForNoWatcher` should also be used to ensure that the
// watcher stops or is killed before continuing.
func ConfigureFastWatcher(ctx context.Context, f *atesting.Fixture) error {
	return f.Configure(ctx, []byte(FastWatcherCfg))
}

// WaitForWatcher loops until a watcher is found running or times out.
func WaitForWatcher(ctx context.Context, timeout time.Duration, interval time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	t := time.NewTicker(interval)
	defer t.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			pids, err := utils.GetWatcherPIDs()
			if err != nil {
				return fmt.Errorf("failed to fetch watcher pids: %w", err)
			}
			if len(pids) > 0 {
				return nil
			}
		}
	}
}

// WaitForNoWatcher loops until no watcher is found running, times out, or
// until the killTimeout is reached.
//
// killTimeout is needed because tests can upgrade to older versions to test
// features in the current build, but that means that when uninstall occurs
// that fixes for the watcher are not present. This ensures that even on an
// installed old build that the watcher is stopped, before uninstall is performed.
func WaitForNoWatcher(ctx context.Context, timeout time.Duration, interval time.Duration, killTimeout time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	t := time.NewTicker(interval)
	defer t.Stop()

	tk := time.NewTimer(killTimeout)
	defer tk.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			pids, err := utils.GetWatcherPIDs()
			if err != nil {
				return fmt.Errorf("failed to fetch watcher pids: %w", err)
			}
			if len(pids) == 0 {
				return nil
			}
		case <-tk.C:
			pids, err := utils.GetWatcherPIDs()
			if err != nil {
				return fmt.Errorf("failed to fetch watcher pids: %w", err)
			}
			if len(pids) == 0 {
				// all good; no watcher anyway
				return nil
			}
			// still watcher running after `killTimeout` we consider it
			// has been long enough. Just kill the watcher because it should
			// have completed with in the `killTimeout` being it didn't means
			// that the running Elastic Agent version does respect `ConfigureFastWatcher`.
			for _, pid := range pids {
				proc, err := os.FindProcess(pid)
				if err == nil {
					_ = killNoneChildProcess(proc)
				}
			}
			// next interval ticker will check for no watcher and exit
		}
	}
}
