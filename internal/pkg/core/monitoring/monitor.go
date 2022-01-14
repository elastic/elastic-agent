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

package monitoring

import (
	"github.com/elastic/elastic-agent-poc/internal/pkg/agent/configuration"
	"github.com/elastic/elastic-agent-poc/internal/pkg/agent/program"
	"github.com/elastic/elastic-agent-poc/internal/pkg/config"
	"github.com/elastic/elastic-agent-poc/internal/pkg/core/monitoring/beats"
)

// Monitor is a monitoring interface providing information about the way
// how application is monitored
type Monitor interface {
	LogPath(spec program.Spec, pipelineID string) string
	MetricsPath(spec program.Spec, pipelineID string) string
	MetricsPathPrefixed(spec program.Spec, pipelineID string) string

	Prepare(spec program.Spec, pipelineID string, uid, gid int) error
	EnrichArgs(spec program.Spec, pipelineID string, args []string, isSidecar bool) []string
	Cleanup(spec program.Spec, pipelineID string) error
	Reload(cfg *config.Config) error
	IsMonitoringEnabled() bool
	MonitoringNamespace() string
	WatchLogs() bool
	WatchMetrics() bool
	Close()
}

// NewMonitor creates a monitor based on a process configuration.
func NewMonitor(cfg *configuration.SettingsConfig) (Monitor, error) {
	logMetrics := true
	if cfg.LoggingConfig != nil {
		logMetrics = cfg.LoggingConfig.Metrics.Enabled
	}
	return beats.NewMonitor(cfg.DownloadConfig, cfg.MonitoringConfig, logMetrics), nil
}
