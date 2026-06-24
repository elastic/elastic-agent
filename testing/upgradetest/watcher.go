// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package upgradetest

import (
	"context"
	"errors"
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
// StateWatching or the timeout is exceeded. Both the start agent and the target
// agent must be >= 8.12.0 for UpgradeDetails to appear in status; older agents
// always return nil details and this function will time out.
//
// It returns immediately on StateFailed or StateRollback so the test does not
// burn the full timeout when an upgrade genuinely fails. If the test may have
// a stale UPG_FAILED from a prior upgrade, call WaitForUpgradeInProgress first
// to confirm the new upgrade has started before calling this function.
//
// It also returns nil if UpgradeDetails transitions from an in-progress state
// to nil, which happens when the watcher finishes its grace period and the
// coordinator clears UpgradeDetails (StateCompleted maps to nil in status).
// This prevents burning the full timeout when the polling interval misses the short
// StateWatching window between agent restart and watcher grace-period expiry. Note: if
// a rollback also completes between two polls (StateRollback → nil), this path
// returns nil as well; WaitHealthyAndVersion and WaitForNoWatcher downstream
// will catch the wrong version or unexpected watcher state in that case.
//
// During StateDownloading, it tracks DownloadPercent and returns an error if
// the percentage does not advance for stallTimeout. Stalls in other states
// (extracting, replacing) are not detected and rely on the outer timeout.
// For larger artifacts, increase stallTimeout accordingly.
//
// Once this returns nil, a separate WaitForWatcher call is not needed.
// WaitForNoWatcher is still needed afterwards to confirm the watcher process
// has actually exited.
//
// Use a generous timeout: artifact downloads can take 10+ minutes on slow CI
// links.
//
// This duplicates the polling pattern in waitUpgradeDetailsState
// (upgradetest/upgrader.go) on purpose. That helper only waits for a target
// state; it does not fail fast on StateFailed/StateRollback and has no download
// stall detection, both of which this function needs.
func WaitForWatchingState(ctx context.Context, f *atesting.Fixture, timeout time.Duration, interval time.Duration, stallTimeout time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	var lastState details.State
	var lastErr error
	var sawInProgress bool
	var lastPercent float64
	var lastProgressAt time.Time

	for {
		select {
		case <-ctx.Done():
			if lastState != "" {
				return fmt.Errorf("upgrade did not reach %s, last observed state: %s: %w", details.StateWatching, lastState, errors.Join(lastErr, ctx.Err()))
			}
			if lastErr != nil {
				return fmt.Errorf("upgrade did not reach %s: %w", details.StateWatching, errors.Join(lastErr, ctx.Err()))
			}
			return fmt.Errorf("upgrade did not reach %s: %w", details.StateWatching, ctx.Err())
		case <-ticker.C:
			// Note: ExecStatus retries internally for up to ~1 minute, so the
			// effective poll cadence may be longer than interval when the agent
			// is restarting. Stall timing is based on wall-clock, not tick count.
			status, err := f.ExecStatus(ctx)
			if err != nil || status.IsZero() {
				// Status may be briefly unavailable during agent restart; retry.
				if err != nil {
					lastErr = err
				} else {
					lastErr = nil // transient zero status; don't carry over a prior error
				}
				continue
			}
			lastErr = nil
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
			case details.StateDownloading:
				sawInProgress = true
				pct := status.UpgradeDetails.Metadata.DownloadPercent
				if lastProgressAt.IsZero() || pct != lastPercent {
					lastPercent = pct
					lastProgressAt = time.Now()
				} else if time.Since(lastProgressAt) > stallTimeout {
					return fmt.Errorf("download stalled at %.1f%% for %s", lastPercent*100, time.Since(lastProgressAt).Round(time.Second))
				}
			default:
				sawInProgress = true
			}
		}
	}
}

// WaitForUpgradeInProgress polls until UpgradeDetails.State is non-nil and
// not StateFailed. Any other state (including StateRollback) is treated as
// in-progress; WaitForWatchingState will fail fast on StateRollback if the
// caller invokes it next. Use this before WaitForWatchingState when a prior
// upgrade may have left a stale UPG_FAILED in the agent status that would
// otherwise cause WaitForWatchingState to fail immediately. Requires the
// running agent to be >= 8.12.0 for UpgradeDetails to appear in status.
//
// Note: if the new upgrade fails fast (before the poller observes a non-failed
// state), this function will time out rather than return an error. In that
// case the failure will only surface as a generic timeout message. Use this
// function only when a stale UPG_FAILED is expected; otherwise call
// WaitForWatchingState directly, which fails fast on StateFailed.
func WaitForUpgradeInProgress(ctx context.Context, f *atesting.Fixture, timeout time.Duration, interval time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	var lastErr error

	for {
		select {
		case <-ctx.Done():
			if lastErr != nil {
				return fmt.Errorf("upgrade did not start: %w", errors.Join(lastErr, ctx.Err()))
			}
			return fmt.Errorf("upgrade did not start: %w", ctx.Err())
		case <-ticker.C:
			status, err := f.ExecStatus(ctx)
			if err != nil || status.IsZero() {
				if err != nil {
					lastErr = err
				} else {
					lastErr = nil
				}
				continue
			}
			lastErr = nil
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
