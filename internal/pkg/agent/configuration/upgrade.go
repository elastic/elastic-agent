// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package configuration

import "time"

const (
	// period during which we monitor for failures resulting in a rollback.
	defaultGracePeriodDuration = 10 * time.Minute

	// interval between checks for new (upgraded) Agent returning an error status.
	defaultStatusCheckInterval = 30 * time.Second

	// period during which an upgraded Agent can be asked to rollback to the previous
	// Agent version on disk.
	defaultRollbackWindowDuration = 7 * 24 * time.Hour // 7 days
)

// UpgradeConfig is the configuration related to Agent upgrades.
type UpgradeConfig struct {
	Watcher  *UpgradeWatcherConfig  `yaml:"watcher" config:"watcher" json:"watcher"`
	Rollback *UpgradeRollbackConfig `yaml:"rollback" config:"rollback" json:"rollback"`
}

type UpgradeWatcherConfig struct {
	GracePeriod time.Duration             `yaml:"grace_period" config:"grace_period" json:"grace_period"`
	ErrorCheck  UpgradeWatcherCheckConfig `yaml:"error_check" config:"error_check" json:"error_check"`
}
type UpgradeWatcherCheckConfig struct {
	Interval time.Duration `yaml:"interval" config:"interval" json:"interval"`
}

type UpgradeRollbackConfig struct {
	Window time.Duration `yaml:"window" config:"window" json:"window"`
}

func DefaultUpgradeConfig() *UpgradeConfig {
	return &UpgradeConfig{
		Watcher: &UpgradeWatcherConfig{
			GracePeriod: defaultGracePeriodDuration,
			ErrorCheck: UpgradeWatcherCheckConfig{
				Interval: defaultStatusCheckInterval,
			},
		},
		Rollback: &UpgradeRollbackConfig{
			Window: defaultRollbackWindowDuration,
		},
	}
}
