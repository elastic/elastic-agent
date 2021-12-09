// Licensed to Elasticsearch B.V. under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Elasticsearch B.V. licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package configuration

import (
	"path/filepath"

	"github.com/elastic/elastic-agent-poc/elastic-agent/pkg/artifact"
	"github.com/elastic/elastic-agent-poc/elastic-agent/pkg/core/logger"
	monitoringCfg "github.com/elastic/elastic-agent-poc/elastic-agent/pkg/core/monitoring/config"
	"github.com/elastic/elastic-agent-poc/elastic-agent/pkg/core/process"
	"github.com/elastic/elastic-agent-poc/elastic-agent/pkg/core/retry"
	"github.com/elastic/elastic-agent-poc/elastic-agent/pkg/core/server"
)

// ExternalInputsPattern is a glob that matches the paths of external configuration files.
var ExternalInputsPattern = filepath.Join("inputs.d", "*.yml")

// SettingsConfig is an collection of agent settings configuration.
type SettingsConfig struct {
	DownloadConfig   *artifact.Config                `yaml:"download" config:"download" json:"download"`
	ProcessConfig    *process.Config                 `yaml:"process" config:"process" json:"process"`
	GRPC             *server.Config                  `yaml:"grpc" config:"grpc" json:"grpc"`
	RetryConfig      *retry.Config                   `yaml:"retry" config:"retry" json:"retry"`
	MonitoringConfig *monitoringCfg.MonitoringConfig `yaml:"monitoring" config:"monitoring" json:"monitoring"`
	LoggingConfig    *logger.Config                  `yaml:"logging,omitempty" config:"logging,omitempty" json:"logging,omitempty"`

	// standalone config
	Reload *ReloadConfig `config:"reload" yaml:"reload" json:"reload"`
	Path   string        `config:"path" yaml:"path" json:"path"`
}

// DefaultSettingsConfig creates a config with pre-set default values.
func DefaultSettingsConfig() *SettingsConfig {
	return &SettingsConfig{
		ProcessConfig:    process.DefaultConfig(),
		RetryConfig:      retry.DefaultConfig(),
		DownloadConfig:   artifact.DefaultConfig(),
		LoggingConfig:    logger.DefaultLoggingConfig(),
		MonitoringConfig: monitoringCfg.DefaultConfig(),
		GRPC:             server.DefaultGRPCConfig(),
		Reload:           DefaultReloadConfig(),
	}
}
