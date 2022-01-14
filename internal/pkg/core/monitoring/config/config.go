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

package config

const defaultPort = 6791
const defaultNamespace = "default"

// MonitoringConfig describes a configuration of a monitoring
type MonitoringConfig struct {
	Enabled        bool                  `yaml:"enabled" config:"enabled"`
	MonitorLogs    bool                  `yaml:"logs" config:"logs"`
	MonitorMetrics bool                  `yaml:"metrics" config:"metrics"`
	LogMetrics     bool                  `yaml:"-" config:"-"`
	HTTP           *MonitoringHTTPConfig `yaml:"http" config:"http"`
	Namespace      string                `yaml:"namespace" config:"namespace"`
	Pprof          *PprofConfig          `yaml:"pprof" config:"pprof"`
}

// MonitoringHTTPConfig is a config defining HTTP endpoint published by agent
// for other processes to watch its metrics.
// Processes are only exposed when HTTP is enabled.
type MonitoringHTTPConfig struct {
	Enabled bool   `yaml:"enabled" config:"enabled"`
	Host    string `yaml:"host" config:"host"`
	Port    int    `yaml:"port" config:"port" validate:"min=0,max=65535,nonzero"`
}

// PprofConfig is a struct for the pprof enablement flag.
// It is a nil struct by default to allow the agent to use the a value that the user has injected into fleet.yml as the source of truth that is passed to beats
// TODO get this value from Kibana?
type PprofConfig struct {
	Enabled bool `yaml:"enabled" config:"enabled"`
}

// DefaultConfig creates a config with pre-set default values.
func DefaultConfig() *MonitoringConfig {
	return &MonitoringConfig{
		Enabled:        true,
		MonitorLogs:    true,
		MonitorMetrics: true,
		LogMetrics:     true,
		HTTP: &MonitoringHTTPConfig{
			Enabled: false,
			Port:    defaultPort,
		},
		Namespace: defaultNamespace,
	}
}
