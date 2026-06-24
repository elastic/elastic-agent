// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package upgradetest

import (
	"context"
	"fmt"
	"os"
	"time"

	atesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/upgrade/details"
	"github.com/elastic/elastic-agent/pkg/utils"
)

// FastWatcherCfg is configuration that makes the watcher run faster.
// we need to set grace period to 100s to be able to detect 5 failures 15 seconds apart and have a little buffer.
const FastWatcherCfg = `
agent.upgrade.watcher:
  grace_period: 100s
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

// WaitForWatchingState polls UpgradeDetails.State until the upgrade reaches
// StateWatching or the timeout is exceeded.
//
// It returns immediately on StateFailed or StateRollback so the test does not
// burn the full timeout when an upgrade genuinely fails. If the test may have
// a stale UPG_FAILED from a prior upgrade, call WaitForUpgradeInProgress first
// to confirm the new upgrade has started before calling this function.
//
// It also returns nil if UpgradeDetails transitions from an in-progress state
// to nil, which happens when the watcher finishes its grace period and the
// coordinator clears UpgradeDetails (StateCompleted maps to nil in status).
// This prevents a 15-minute hang when the polling interval misses the short
// StateWatching window between agent restart and watcher completion.
//
// Once this returns nil, a separate WaitForWatcher call is not needed.
//
// Use a generous timeout: artifact downloads can take 10+ minutes on slow CI
// links.
func WaitForWatchingState(ctx context.Context, f *atesting.Fixture, timeout time.Duration, interval time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	var lastState details.State
	var lastErr error
	var sawInProgress bool

	for {
		select {
		case <-ctx.Done():
			if lastState != "" {
				return fmt.Errorf("timed out waiting for upgrade to reach %s, last observed state: %s: %w", details.StateWatching, lastState, ctx.Err())
			}
			if lastErr != nil {
				return fmt.Errorf("timed out waiting for upgrade to reach %s: %w", details.StateWatching, lastErr)
			}
			return fmt.Errorf("timed out waiting for upgrade to reach %s: %w", details.StateWatching, ctx.Err())
		case <-ticker.C:
			status, err := f.ExecStatus(ctx)
			if err != nil || status.IsZero() {
				// Status may be briefly unavailable during agent restart; retry.
				lastErr = err
				continue
			}
			if status.UpgradeDetails == nil {
				// If the upgrade was previously in progress, nil means the watcher
				// completed its grace period and the coordinator cleared UpgradeDetails.
				if sawInProgress {
					return nil
				}
				continue
			}

			state := status.UpgradeDetails.State
			lastState = state

			switch state {
			case details.StateWatching:
				return nil
			case details.StateFailed:
				errMsg := status.UpgradeDetails.Metadata.ErrorMsg
				if errMsg == "" {
					errMsg = fmt.Sprintf("failed from state %s", status.UpgradeDetails.Metadata.FailedState)
				}
				return fmt.Errorf("upgrade failed while waiting for %s: %s", details.StateWatching, errMsg)
			case details.StateRollback:
				errMsg := status.UpgradeDetails.Metadata.ErrorMsg
				if errMsg == "" {
					errMsg = fmt.Sprintf("rollback from state %s", status.UpgradeDetails.Metadata.FailedState)
				}
				return fmt.Errorf("upgrade watcher triggered rollback while waiting for %s: %s", details.StateWatching, errMsg)
			default:
				sawInProgress = true
			}
		}
	}
}

// WaitForUpgradeInProgress polls until UpgradeDetails.State is non-nil and
// not StateFailed. Use this before WaitForWatchingState when a prior upgrade
// may have left a stale UPG_FAILED in the agent status that would otherwise
// cause WaitForWatchingState to fail immediately.
func WaitForUpgradeInProgress(ctx context.Context, f *atesting.Fixture, timeout time.Duration, interval time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("timed out waiting for upgrade to start: %w", ctx.Err())
		case <-ticker.C:
			status, err := f.ExecStatus(ctx)
			if err != nil || status.IsZero() {
				continue
			}
			if status.UpgradeDetails == nil || status.UpgradeDetails.State == details.StateFailed {
				continue
			}
			return nil
		}
	}
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
