// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package configuration

import "time"

const (
	// period during which we monitor for failures resulting in a rollback.
	defaultGracePeriodDuration = 10 * time.Minute

	// interval between checks for new (upgraded) Agent returning an error status.
	defaultStatusCheckInterval = 30 * time.Second

	// interval between checks for new (upgraded) Agent crashing.
	defaultCrashCheckInterval = 10 * time.Second

	// interval between checks for Agent uninstall.
	defaultInstallCheckInterval = 10 * time.Second
)

// UpgradeConfig is the configuration related to Agent upgrades.
type UpgradeConfig struct {
	Watcher *UpgradeWatcherConfig `yaml:"watcher" config:"watcher" json:"watcher"`
}

type UpgradeWatcherConfig struct {
	GracePeriod  time.Duration             `yaml:"grace_period" config:"grace_period" json:"grace_period"`
	ErrorCheck   UpgradeWatcherCheckConfig `yaml:"error_check" config:"error_check" json:"error_check"`
	CrashCheck   UpgradeWatcherCheckConfig `yaml:"crash_check" config:"crash_check" json:"crash_check"`
	InstallCheck UpgradeWatcherCheckConfig `yaml:"install_check" config:"install_check" json:"install_check"`
}
type UpgradeWatcherCheckConfig struct {
	Interval time.Duration `yaml:"interval" config:"interval" json:"interval"`
}

func DefaultUpgradeConfig() *UpgradeConfig {
	return &UpgradeConfig{
		Watcher: &UpgradeWatcherConfig{
			GracePeriod: defaultGracePeriodDuration,
			ErrorCheck: UpgradeWatcherCheckConfig{
				Interval: defaultStatusCheckInterval,
			},
			CrashCheck: UpgradeWatcherCheckConfig{
				Interval: defaultCrashCheckInterval,
			},
			InstallCheck: UpgradeWatcherCheckConfig{
				Interval: defaultInstallCheckInterval,
			},
		},
	}
}
