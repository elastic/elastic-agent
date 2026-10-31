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

const (
	// FastWatcherGracePeriod is the grace period used by FastWatcherCfg.
	//
	// The upgraded agent gets statusCheckMissesAllowed+1 (5) connection attempts,
	// one every FastWatcherErrorCheckInterval, before the watcher rolls back, so
	// the interval bounds how long the agent may take to restart: 10s leaves 50s,
	// which covers the 20+ s a slow Windows VM needs. The grace period only has to
	// outlast that window plus the time PerformUpgrade needs to observe the
	// UPG_WATCHING state (typically <20 s after the marker is written). 60s does
	// that and removes ~40 s of idle waiting from every upgrade compared with the
	// previous 100s/15s configuration. Tests that need the watcher to stay alive
	// for longer should use WatcherCfg with their own grace period.
	FastWatcherGracePeriod = 60 * time.Second
	// FastWatcherErrorCheckInterval is the error check interval used by FastWatcherCfg.
	FastWatcherErrorCheckInterval = 10 * time.Second

	// StatusPollInterval is how often the upgrade helpers poll `elastic-agent status`
	// and similar cheap local checks while waiting for a state change.
	StatusPollInterval = 2 * time.Second
	// WatcherPollInterval is how often the upgrade helpers scan the process list
	// for the upgrade watcher.
	WatcherPollInterval = time.Second
)

// FastWatcherCfg is configuration that makes the watcher run faster.
// See FastWatcherGracePeriod for how the values were chosen.
var FastWatcherCfg = WatcherCfg(FastWatcherGracePeriod, FastWatcherErrorCheckInterval)

// WatcherCfg returns an Elastic Agent configuration snippet that sets the
// upgrade watcher grace period and error check interval.
func WatcherCfg(gracePeriod, errorCheckInterval time.Duration) string {
	return fmt.Sprintf(`
agent.upgrade.watcher:
  grace_period: %s
  error_check.interval: %s
`, gracePeriod, errorCheckInterval)
}

// ConfigureFastWatcher writes an Elastic Agent configuration that
// adjusts the watcher to be faster.
//
// Note: Not all versions or modes of the Elastic Agent respect this option
// that is why the `WaitForNoWatcher` should also be used to ensure that the
// watcher stops or is killed before continuing.
func ConfigureFastWatcher(ctx context.Context, f *atesting.Fixture) error {
	return f.Configure(ctx, []byte(FastWatcherCfg))
}

// WaitForWatchingState polls UpgradeDetails until the upgrade reaches
// StateWatching or the coordinator clears the details (upgrade completed).
// Returns immediately on StateFailed or StateRollback. During StateDownloading,
// returns an error if DownloadPercent does not advance for stallTimeout.
//
// Callers must ensure an upgrade is already in progress before calling this
// (e.g. via WaitForUpgradeInProgress) — nil details are treated as completion.
func WaitForWatchingState(ctx context.Context, f *atesting.Fixture, timeout time.Duration, interval time.Duration, stallTimeout time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	var lastState details.State
	var lastPercent float64
	var lastProgressAt time.Time

	for {
		select {
		case <-ctx.Done():
			if lastState != "" {
				return fmt.Errorf("upgrade did not reach %s, last state: %s: %w", details.StateWatching, lastState, ctx.Err())
			}
			return fmt.Errorf("upgrade did not reach %s: %w", details.StateWatching, ctx.Err())
		case <-ticker.C:
			status, err := f.ExecStatus(ctx)
			if err != nil || status.IsZero() {
				continue
			}
			if status.UpgradeDetails == nil {
				return nil // coordinator cleared details: upgrade completed
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
				return fmt.Errorf("upgrade failed: %s", errMsg)
			case details.StateRollback:
				errMsg := status.UpgradeDetails.Metadata.ErrorMsg
				if errMsg == "" {
					errMsg = fmt.Sprintf("rollback from state %s", status.UpgradeDetails.Metadata.FailedState)
				}
				return fmt.Errorf("upgrade rolled back: %s", errMsg)
			case details.StateDownloading:
				pct := status.UpgradeDetails.Metadata.DownloadPercent
				if lastProgressAt.IsZero() || pct != lastPercent {
					lastPercent = pct
					lastProgressAt = time.Now()
				} else if time.Since(lastProgressAt) > stallTimeout {
					return fmt.Errorf("download stalled at %.1f%% for %s", lastPercent*100, time.Since(lastProgressAt).Round(time.Second))
				}
			}
		}
	}
}

// WaitForUpgradeInProgress polls until UpgradeDetails is non-nil and not
// StateFailed. Use before WaitForWatchingState when a prior upgrade may have
// left a stale UPG_FAILED that would otherwise cause an immediate failure.
func WaitForUpgradeInProgress(ctx context.Context, f *atesting.Fixture, timeout time.Duration, interval time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("upgrade did not start: %w", ctx.Err())
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
