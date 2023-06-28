// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package configuration

import (
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact"

	monitoringCfg "github.com/elastic/elastic-agent/internal/pkg/core/monitoring/config"
	"github.com/elastic/elastic-agent/pkg/core/logger"
	"github.com/elastic/elastic-agent/pkg/core/process"
)

// SettingsConfig is an collection of agent settings configuration.
type SettingsConfig struct {
	ID               string                          `yaml:"id" config:"id" json:"id"`
	DownloadConfig   *artifact.Config                `yaml:"download" config:"download" json:"download"`
	ProcessConfig    *process.Config                 `yaml:"process" config:"process" json:"process"`
	GRPC             *GRPCConfig                     `yaml:"grpc" config:"grpc" json:"grpc"`
	MonitoringConfig *monitoringCfg.MonitoringConfig `yaml:"monitoring" config:"monitoring" json:"monitoring"`
	LoggingConfig    *logger.Config                  `yaml:"logging,omitempty" config:"logging,omitempty" json:"logging,omitempty"`
	Upgrade          *UpgradeConfig                  `yaml:"upgrade" config:"upgrade" json:"upgrade"
`
	// standalone config
	Reload              *ReloadConfig `config:"reload" yaml:"reload" json:"reload"`
	Path                string        `config:"path" yaml:"path" json:"path"`
	V1MonitoringEnabled bool          `config:"v1_monitoring_enabled" yaml:"v1_monitoring_enabled" json:"v1_monitoring_enabled"`
}

// DefaultSettingsConfig creates a config with pre-set default values.
func DefaultSettingsConfig() *SettingsConfig {
	return &SettingsConfig{
		ProcessConfig:       process.DefaultConfig(),
		DownloadConfig:      artifact.DefaultConfig(),
		LoggingConfig:       logger.DefaultLoggingConfig(),
		MonitoringConfig:    monitoringCfg.DefaultConfig(),
		GRPC:                DefaultGRPCConfig(),
		Upgrade:             DefaultUpgradeConfig(),
		Reload:              DefaultReloadConfig(),
		V1MonitoringEnabled: true,
	}
}
