// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package cmd

import (
	"fmt"
	"runtime"
	"time"

	"github.com/gofrs/uuid"

	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/elastic-agent-libs/monitoring"
	"github.com/elastic/elastic-agent-system-metrics/metric/system/process"
	"github.com/elastic/elastic-agent-system-metrics/report"
)

var (
	systemMetrics *monitoring.Registry
	beatMetrics   *monitoring.Registry

	processStats *process.Stats
	ephemeralID  uuid.UUID
	startTime    time.Time
)

func init() {
	systemMetrics = monitoring.Default.NewRegistry("system")
	beatMetrics = monitoring.Default.NewRegistry("beat")
	startTime = time.Now()

	var err error
	ephemeralID, err = uuid.NewV4()
	if err != nil {
		logp.Err("Error while generating ephemeral ID for Beat")
	}
}

// monitoringCgroupsHierarchyOverride is an undocumented environment variable which
// overrides the cgroups path under /sys/fs/cgroup, which should be set to "/" when running
// Elastic Agent under Docker.
const monitoringCgroupsHierarchyOverride = "LIBBEAT_MONITORING_CGROUPS_HIERARCHY_OVERRIDE"

func initMetrics(logger *logp.Logger, name, version string) error {
	monitoring.NewFunc(systemMetrics, "cpu", report.ReportSystemCPUUsage, monitoring.Report)

	name = processName(name)
	processStats = &process.Stats{
		Procs:        []string{name},
		EnvWhitelist: nil,
		CPUTicks:     true,
		CacheCmdLine: true,
		IncludeTop:   process.IncludeTopConfig{},
	}

	err := processStats.Init()
	if err != nil {
		return fmt.Errorf("failed to init process stats for agent: %w", err)
	}

	monitoring.NewFunc(beatMetrics, "memstats", report.MemStatsReporter(logger, processStats), monitoring.Report)
	monitoring.NewFunc(beatMetrics, "cpu", report.InstanceCPUReporter(logger, processStats), monitoring.Report)
	monitoring.NewFunc(beatMetrics, "runtime", report.ReportRuntime, monitoring.Report)
	monitoring.NewFunc(beatMetrics, "info", infoReporter(name, version), monitoring.Report)

	setupPlatformSpecificMetrics(logger, processStats)

	return nil
}

// processName truncates the name if it is longer than 15 characters, so we don't fail process checks later on
// On *nix, the process name comes from /proc/PID/stat, which uses a comm value of 16 bytes, plus the null byte
func processName(name string) string {
	if (isLinux() || isDarwin()) && len(name) > 15 {
		name = name[:15]
	}
	return name
}

func isDarwin() bool {
	return runtime.GOOS == "darwin"
}

func isLinux() bool {
	return runtime.GOOS == "linux"
}

func isWindows() bool {
	return runtime.GOOS == "windows"
}

func infoReporter(serviceName, version string) func(_ monitoring.Mode, V monitoring.Visitor) {
	return func(_ monitoring.Mode, V monitoring.Visitor) {
		V.OnRegistryStart()
		defer V.OnRegistryFinished()

		delta := time.Since(startTime)
		uptime := int64(delta / time.Millisecond)
		monitoring.ReportNamespace(V, "uptime", func() {
			monitoring.ReportInt(V, "ms", uptime)
		})

		monitoring.ReportString(V, "ephemeral_id", ephemeralID.String())
		monitoring.ReportString(V, "name", serviceName)
		monitoring.ReportString(V, "version", version)
	}
}

func setupPlatformSpecificMetrics(logger *logp.Logger, processStats *process.Stats) {
	if isLinux() {
		monitoring.NewFunc(beatMetrics, "cgroup", report.InstanceCroupsReporter(logger, monitoringCgroupsHierarchyOverride), monitoring.Report)
	}

	if isWindows() {
		report.SetupWindowsHandlesMetrics(logger, systemMetrics)
	} else {
		monitoring.NewFunc(systemMetrics, "load", report.ReportSystemLoadAverage, monitoring.Report)
	}

	report.SetupLinuxBSDFDMetrics(logger, systemMetrics, processStats)
}

// EphemeralID returns generated EphemeralID
func EphemeralID() uuid.UUID {
	return ephemeralID
}
