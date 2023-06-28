package configuration

import "time"

// period during which we monitor for failures resulting in a rollback
const defaultGracePeriodDuration = 10 * time.Minute

// UpgradeConfig is the configuration related to Agent upgrades.
type UpgradeConfig struct {
	Watcher *UpgradeWatcherConfig `yaml:"watcher" config:"watcher" json:"watcher"`
}

type UpgradeWatcherConfig struct {
	GracePeriod time.Duration `yaml:"grace_period" config:"grace_period" json:"grace_period"`
}

func DefaultUpgradeConfig() *UpgradeConfig {
	return &UpgradeConfig{
		Watcher: &UpgradeWatcherConfig{
			GracePeriod: defaultGracePeriodDuration,
		},
	}
}
