// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package configuration

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/internal/pkg/config"
)

func TestParseUpgradeConfig(t *testing.T) {
	tests := map[string]struct {
		cfg      map[string]any
		expected UpgradeConfig
	}{
		"default": {
			cfg: map[string]any{},
			expected: UpgradeConfig{
				Watcher: &UpgradeWatcherConfig{
					GracePeriod: defaultGracePeriodDuration,
					ErrorCheck: UpgradeWatcherCheckConfig{
						Interval: defaultStatusCheckInterval,
					},
				},
				Rollback: &UpgradeRollbackConfig{
					Window:          defaultRollbackWindowDuration,
					CleanupInterval: defaultRollbackCleanupInterval,
					LogsRetention:   defaultLogsRetentionDuration,
				},
			},
		},
		"watcher_grace_period": {
			cfg: map[string]any{
				"watcher": map[string]any{
					"grace_period": "2m",
				},
			},
			expected: UpgradeConfig{
				Watcher: &UpgradeWatcherConfig{
					GracePeriod: 2 * time.Minute,
					ErrorCheck: UpgradeWatcherCheckConfig{
						Interval: defaultStatusCheckInterval,
					},
				},
				Rollback: &UpgradeRollbackConfig{
					Window:          defaultRollbackWindowDuration,
					CleanupInterval: defaultRollbackCleanupInterval,
					LogsRetention:   defaultLogsRetentionDuration,
				},
			},
		},
		"watcher_error_check_interval": {
			cfg: map[string]any{
				"watcher": map[string]any{
					"error_check": map[string]any{
						"interval": "1h",
					},
				},
			},
			expected: UpgradeConfig{
				Watcher: &UpgradeWatcherConfig{
					GracePeriod: defaultGracePeriodDuration,
					ErrorCheck: UpgradeWatcherCheckConfig{
						Interval: 1 * time.Hour,
					},
				},
				Rollback: &UpgradeRollbackConfig{
					Window:          defaultRollbackWindowDuration,
					CleanupInterval: defaultRollbackCleanupInterval,
					LogsRetention:   defaultLogsRetentionDuration,
				},
			},
		},
		"rollback_window": {
			cfg: map[string]any{
				"rollback.window": "8h",
			},
			expected: UpgradeConfig{
				Watcher: &UpgradeWatcherConfig{
					GracePeriod: defaultGracePeriodDuration,
					ErrorCheck: UpgradeWatcherCheckConfig{
						Interval: defaultStatusCheckInterval,
					},
				},
				Rollback: &UpgradeRollbackConfig{
					Window:          8 * time.Hour,
					CleanupInterval: defaultRollbackCleanupInterval,
					LogsRetention:   defaultLogsRetentionDuration,
				},
			},
		},
		"cleanup_interval": {
			cfg: map[string]any{
				"rollback.cleanup_interval": "1m",
			},
			expected: UpgradeConfig{
				Watcher: &UpgradeWatcherConfig{
					GracePeriod: defaultGracePeriodDuration,
					ErrorCheck: UpgradeWatcherCheckConfig{
						Interval: defaultStatusCheckInterval,
					},
				},
				Rollback: &UpgradeRollbackConfig{
					Window:          defaultRollbackWindowDuration,
					CleanupInterval: 1 * time.Minute,
					LogsRetention:   defaultLogsRetentionDuration,
				},
			},
		},
		"logs_retention": {
			cfg: map[string]any{
				"rollback.logs_retention": "48h",
			},
			expected: UpgradeConfig{
				Watcher: &UpgradeWatcherConfig{
					GracePeriod: defaultGracePeriodDuration,
					ErrorCheck: UpgradeWatcherCheckConfig{
						Interval: defaultStatusCheckInterval,
					},
				},
				Rollback: &UpgradeRollbackConfig{
					Window:          defaultRollbackWindowDuration,
					CleanupInterval: defaultRollbackCleanupInterval,
					LogsRetention:   48 * time.Hour,
				},
			},
		},
		"logs_retention_disabled": {
			cfg: map[string]any{
				"rollback.logs_retention": "0s",
			},
			expected: UpgradeConfig{
				Watcher: &UpgradeWatcherConfig{
					GracePeriod: defaultGracePeriodDuration,
					ErrorCheck: UpgradeWatcherCheckConfig{
						Interval: defaultStatusCheckInterval,
					},
				},
				Rollback: &UpgradeRollbackConfig{
					Window:          defaultRollbackWindowDuration,
					CleanupInterval: defaultRollbackCleanupInterval,
					LogsRetention:   0,
				},
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			c := DefaultUpgradeConfig()
			cfg := config.MustNewConfigFrom(test.cfg)
			require.NoError(t, cfg.UnpackTo(c))
			require.Equal(t, test.expected, *c)
		})
	}
}
