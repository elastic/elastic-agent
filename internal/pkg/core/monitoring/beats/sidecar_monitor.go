// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package beats

import (
	"fmt"
	"os"

	"github.com/elastic/elastic-agent/internal/pkg/agent/configuration"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/internal/pkg/agent/program"
	"github.com/elastic/elastic-agent/internal/pkg/artifact"
	"github.com/elastic/elastic-agent/internal/pkg/config"
	monitoringConfig "github.com/elastic/elastic-agent/internal/pkg/core/monitoring/config"
)

// SidecarMonitor is a provides information about the way how beat is monitored
type SidecarMonitor struct {
	operatingSystem string
	config          *monitoringConfig.MonitoringConfig
}

// NewSidecarMonitor creates a beats sidecar monitor, functionality is restricted purely on exposing
// http endpoint for diagnostics.
func NewSidecarMonitor(downloadConfig *artifact.Config, monitoringCfg *monitoringConfig.MonitoringConfig) *SidecarMonitor {
	if monitoringCfg == nil {
		monitoringCfg = monitoringConfig.DefaultConfig()
		monitoringCfg.Pprof = &monitoringConfig.PprofConfig{Enabled: false}
		monitoringCfg.HTTP.Buffer = &monitoringConfig.BufferConfig{Enabled: false}
	}

	return &SidecarMonitor{
		operatingSystem: downloadConfig.OS(),
		config:          monitoringCfg,
	}
}

// Reload reloads state of the monitoring based on config.
func (b *SidecarMonitor) Reload(rawConfig *config.Config) error {
	cfg := configuration.DefaultConfiguration()
	if err := rawConfig.Unpack(&cfg); err != nil {
		return err
	}

	if cfg == nil || cfg.Settings == nil || cfg.Settings.MonitoringConfig == nil {
		b.config = monitoringConfig.DefaultConfig()
	} else {
		if cfg.Settings.MonitoringConfig.Pprof == nil {
			cfg.Settings.MonitoringConfig.Pprof = b.config.Pprof
		}
		if cfg.Settings.MonitoringConfig.HTTP.Buffer == nil {
			cfg.Settings.MonitoringConfig.HTTP.Buffer = b.config.HTTP.Buffer
		}
		b.config = cfg.Settings.MonitoringConfig
	}

	return nil
}

// EnrichArgs enriches arguments provided to application, in order to enable
// monitoring
func (b *SidecarMonitor) EnrichArgs(spec program.Spec, pipelineID string, args []string) []string {
	appendix := make([]string, 0, 7)

	if endpoint := MonitoringEndpoint(spec, b.operatingSystem, pipelineID, true); endpoint != "" {
		appendix = append(appendix,
			"-E", "http.enabled=true",
			"-E", "http.host="+endpoint,
		)
		if b.config.Pprof != nil && b.config.Pprof.Enabled {
			appendix = append(appendix,
				"-E", "http.pprof.enabled=true",
			)
		}
		if b.config.HTTP.Buffer != nil && b.config.HTTP.Buffer.Enabled {
			appendix = append(appendix,
				"-E", "http.buffer.enabled=true",
			)
		}
	}

	return append(args, appendix...)
}

// Cleanup cleans up all drops.
func (b *SidecarMonitor) Cleanup(spec program.Spec, pipelineID string) error {
	endpoint := MonitoringEndpoint(spec, b.operatingSystem, pipelineID, true)
	drop := monitoringDrop(endpoint)

	return os.RemoveAll(drop)
}

// Close disables monitoring
func (b *SidecarMonitor) Close() {
	b.config.Enabled = false
	b.config.MonitorMetrics = false
	b.config.MonitorLogs = false
}

// Prepare executes steps in order for monitoring to work correctly
func (b *SidecarMonitor) Prepare(spec program.Spec, pipelineID string, uid, gid int) error {
	endpoint := MonitoringEndpoint(spec, b.operatingSystem, pipelineID, true)
	drop := monitoringDrop(endpoint)

	if err := os.MkdirAll(drop, 0775); err != nil {
		return errors.New(err, fmt.Sprintf("failed to create a directory %q", drop))
	}

	if err := changeOwner(drop, uid, gid); err != nil {
		return errors.New(err, fmt.Sprintf("failed to change owner of a directory %q", drop))
	}

	return nil
}

// LogPath describes a path where application stores logs. Empty if
// application is not monitorable
func (b *SidecarMonitor) LogPath(program.Spec, string) string {
	return ""
}

// MetricsPath describes a location where application exposes metrics
// collectable by metricbeat.
func (b *SidecarMonitor) MetricsPath(program.Spec, string) string {
	return ""
}

// MetricsPathPrefixed return metrics path prefixed with http+ prefix.
func (b *SidecarMonitor) MetricsPathPrefixed(program.Spec, string) string {
	return ""
}

// IsMonitoringEnabled returns true if monitoring is configured.
func (b *SidecarMonitor) IsMonitoringEnabled() bool { return false }

// WatchLogs return true if monitoring is configured and monitoring logs is enabled.
func (b *SidecarMonitor) WatchLogs() bool { return false }

// WatchMetrics return true if monitoring is configured and monitoring metrics is enabled.
func (b *SidecarMonitor) WatchMetrics() bool { return false }

// MonitoringNamespace returns monitoring namespace configured.
func (b *SidecarMonitor) MonitoringNamespace() string { return "default" }
