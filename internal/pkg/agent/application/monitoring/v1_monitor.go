// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package monitoring

import (
	"crypto/sha256"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"unicode"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/internal/pkg/config"
	monitoringCfg "github.com/elastic/elastic-agent/internal/pkg/core/monitoring/config"
)

const (
	// args: data path, pipeline name, application name
	logFileFormat = "%s/logs/%s"
	// args: data path, install path, pipeline name, application name
	logFileFormatWin = "%s\\logs\\%s"

	// args: pipeline name, application name
	mbEndpointFileFormatWin = `npipe:///%s`

	// args: pipeline name, application name
	agentMbEndpointFileFormatWin = `npipe:///elastic-agent`
	// agentMbEndpointHTTP is used with cloud and exposes metrics on http endpoint
	agentMbEndpointHTTP = "http://%s:%d"
	httpPlusPrefix      = "http+"

	defaultOutputName          = "default"
	outputsKey                 = "outputs"
	inputsKey                  = "inputs"
	idKey                      = "id"
	agentKey                   = "agent"
	monitoringKey              = "monitoring"
	useOutputKey               = "use_output"
	monitoringOutput           = "monitoring"
	defaultMonitoringNamespace = "default"
	agentName                  = "elastic-agent"

	windowsOS = "windows"
)

var (
	supportedComponents = []string{"filebeat", "metricbeat", "apm-server", "auditbeat", "cloudbeat", "endpoint-security", "fleet-server", "heartbeat", "osquerybeat", "packetbeat"}
)

type BeatsMonitor struct {
	enabled         bool // feature flag disabling whole v1 monitoring story
	config          *monitoringConfig
	operatingSystem string
	agentInfo       *info.AgentInfo
}

type monitoringConfig struct {
	C *monitoringCfg.MonitoringConfig `config:"agent.monitoring"`
}

func New(enabled bool, operatingSystem string, cfg *monitoringCfg.MonitoringConfig, agentInfo *info.AgentInfo) *BeatsMonitor {
	return &BeatsMonitor{
		enabled: enabled,
		config: &monitoringConfig{
			C: cfg,
		},
		operatingSystem: operatingSystem,
		agentInfo:       agentInfo,
	}
}

// Enabled returns true if monitoring is enabled and at least one of logs and metrics should be collected.
func (b *BeatsMonitor) Enabled() bool {
	return b.enabled && b.config.C.Enabled && (b.config.C.MonitorLogs || b.config.C.MonitorMetrics)
}

func (b *BeatsMonitor) Reload(rawConfig *config.Config) error {
	if !b.Enabled() {
		return nil
	}

	if err := rawConfig.Unpack(&b.config); err != nil {
		return errors.New(err, "failed to unpack monitoring config during reload")
	}
	return nil
}

func (b *BeatsMonitor) InjectMonitoring(cfg map[string]interface{}, components []string) error {
	if !b.Enabled() {
		return nil
	}

	monitoringOutputName := defaultOutputName
	if agentCfg, found := cfg[agentKey]; found {
		agentCfgMap, ok := agentCfg.(map[string]interface{})
		if ok {
			if monitoringCfg, found := agentCfgMap[monitoringKey]; found {
				monitoringMap, ok := monitoringCfg.(map[string]interface{})
				if ok {
					if use, found := monitoringMap[useOutputKey]; found {
						if useStr, ok := use.(string); ok {
							monitoringOutputName = useStr
						}
					}
				}
			}
		}
	}

	if err := b.injectMonitoringOutput(cfg, monitoringOutputName); err != nil {
		return errors.New(err, "failed to inject monitoring output")
	}

	if b.config.C.MonitorLogs {
		if err := b.injectLogsInput(cfg, components, monitoringOutputName); err != nil {
			return errors.New(err, "failed to inject monitoring output")
		}
	}

	if b.config.C.MonitorMetrics {
		if err := b.injectMetricsInput(cfg, components, monitoringOutputName); err != nil {
			return errors.New(err, "failed to inject monitoring output")
		}
	}
	return nil
}

// EnrichArgs enriches arguments provided to application, in order to enable
// monitoring
func (b *BeatsMonitor) EnrichArgs(unit string, args []string) []string {
	if !b.enabled {
		// even if monitoring is disabled enrich args.
		// the only way to skip it is by disabling monitoring by feature flag
		return args
	}

	// only beats understands these flags
	if !strings.Contains(unit, "beat-") {
		return args
	}

	appendix := make([]string, 0, 20)
	endpoint := endpointPath(unit, b.operatingSystem)
	if endpoint != "" {
		appendix = append(appendix,
			"-E", "http.enabled=true",
			"-E", "http.host="+endpoint,
		)
		if b.config.C.Pprof != nil && b.config.C.Pprof.Enabled {
			appendix = append(appendix,
				"-E", "http.pprof.enabled=true",
			)
		}
		if b.config.C.HTTP.Buffer != nil && b.config.C.HTTP.Buffer.Enabled {
			appendix = append(appendix,
				"-E", "http.buffer.enabled=true",
			)
		}
	}

	loggingPath := loggingPath(unit, b.operatingSystem)
	if loggingPath != "" {
		appendix = append(appendix,
			"-E", "logging.files.path="+filepath.Dir(loggingPath),
			"-E", "logging.files.name="+filepath.Base(loggingPath),
			"-E", "logging.files.keepfiles=7",
			"-E", "logging.files.permission=0640",
			"-E", "logging.files.interval=1h",
		)

		if !b.config.C.LogMetrics {
			appendix = append(appendix,
				"-E", "logging.metrics.enabled=false",
			)
		}
	}

	return append(args, appendix...)
}

// Prepare executes steps in order for monitoring to work correctly
func (b *BeatsMonitor) Prepare() error {
	if !b.Enabled() {
		return nil
	}
	drops := make([]string, 0, 2)
	if b.config.C.MonitorLogs {
		logsDrop := loggingPath("unit", b.operatingSystem)
		drops = append(drops, filepath.Dir(logsDrop))
	}

	if b.config.C.MonitorMetrics {
		metricsDrop := endpointPath("unit", b.operatingSystem)
		drops = append(drops, filepath.Dir(metricsDrop))
	}

	for _, drop := range drops {
		if drop == "" {
			continue
		}

		// skip if already exists
		if _, err := os.Stat(drop); err != nil {
			if !os.IsNotExist(err) {
				return err
			}

			// create
			if err := os.MkdirAll(drop, 0775); err != nil {
				return errors.New(err, fmt.Sprintf("failed to create directory %q", drop))
			}

			uid, gid := os.Geteuid(), os.Getegid()
			if err := changeOwner(drop, uid, gid); err != nil {
				return errors.New(err, fmt.Sprintf("failed to change owner of directory %q", drop))
			}
		}
	}

	return nil
}

// Cleanup removes
func (b *BeatsMonitor) Cleanup(unit string) error {
	if !b.Enabled() {
		return nil
	}

	endpoint := monitoringFile(unit, b.operatingSystem)
	if endpoint == "" {
		return nil
	}

	return os.RemoveAll(endpoint)
}

func (b *BeatsMonitor) injectMonitoringOutput(cfg map[string]interface{}, monitoringOutputName string) error {
	if monitoringOutputName == monitoringOutput {
		// no work needed
		return nil
	}

	outputsNode, found := cfg[outputsKey]
	if !found {
		return fmt.Errorf("outputs not part of the config")
	}

	outputs, ok := outputsNode.(map[string]interface{})
	if !ok {
		return fmt.Errorf("outputs not a map")
	}

	outputNode, found := outputs[monitoringOutputName]
	if !found {
		return fmt.Errorf("output %q used for monitoring not found", monitoringOutputName)
	}

	outputs[monitoringOutput] = outputNode
	return nil
}

func (b *BeatsMonitor) injectLogsInput(cfg map[string]interface{}, units []string, monitoringOutput string) error {
	monitoringNamespace := b.monitoringNamespace()
	logsDrop := filepath.Dir(loggingPath("unit", b.operatingSystem))

	agentID := b.agentInfo.AgentID()
	version := b.agentInfo.Version()
	isSnapshot := b.agentInfo.Snapshot()

	inputs := []interface{}{
		map[string]interface{}{
			"type":       "filestream",
			idKey:        "logs-monitoring-agent",
			useOutputKey: monitoringOutput,
			"close": map[string]interface{}{
				"on_state_change": map[string]interface{}{
					"inactive": "5m",
				},
			},
			"parsers": []map[string]interface{}{
				{
					"ndjson": map[string]interface{}{
						"overwrite_keys": true,
						"message_key":    "message",
					},
				},
			},
			"paths": []string{
				filepath.Join(logsDrop, agentName+"-*.ndjson"),
				filepath.Join(logsDrop, agentName+"-watcher-*.ndjson"),
			},
			"index": fmt.Sprintf("logs-elastic_agent-%s", monitoringNamespace),
			"processors": []map[string]interface{}{
				{
					"add_fields": map[string]interface{}{
						"target": "data_stream",
						"fields": map[string]interface{}{
							"type":      "logs",
							"dataset":   "elastic_agent",
							"namespace": monitoringNamespace,
						},
					},
				},
				{
					"add_fields": map[string]interface{}{
						"target": "event",
						"fields": map[string]interface{}{
							"dataset": "elastic_agent",
						},
					},
				},
				{
					"add_fields": map[string]interface{}{
						"target": "elastic_agent",
						"fields": map[string]interface{}{
							"id":       agentID,
							"version":  version,
							"snapshot": isSnapshot,
						},
					},
				},
				{
					"add_fields": map[string]interface{}{
						"target": "agent",
						"fields": map[string]interface{}{
							"id": agentID,
						},
					},
				},
				{
					"drop_fields": map[string]interface{}{
						"fields": []string{
							"ecs.version", //coming from logger, already added by libbeat
						},
						"ignore_missing": true,
					},
				},
			},
		},
	}

	for _, unit := range units {
		name, isSupported := componentName(unit)
		if !isSupported {
			continue
		}

		name = strings.ReplaceAll(name, "-", "_") // conform with index naming policy
		logFile := loggingPath(unit, b.operatingSystem)
		inputs = append(inputs, map[string]interface{}{
			"type":       "filestream",
			idKey:        "logs-monitoring-" + name,
			useOutputKey: monitoringOutput,
			"close": map[string]interface{}{
				"on_state_change": map[string]interface{}{
					"inactive": "5m",
				},
			},
			"parsers": []map[string]interface{}{
				{
					"ndjson": map[string]interface{}{
						"overwrite_keys": true,
						"message_key":    "message",
					},
				},
			},
			"paths": []string{logFile, logFile + "*"},
			"index": fmt.Sprintf("logs-elastic_agent.%s-%s", name, monitoringNamespace),
			"processors": []map[string]interface{}{
				{
					"add_fields": map[string]interface{}{
						"target": "data_stream",
						"fields": map[string]interface{}{
							"type":      "logs",
							"dataset":   fmt.Sprintf("elastic_agent.%s", name),
							"namespace": monitoringNamespace,
						},
					},
				},
				{
					"add_fields": map[string]interface{}{
						"target": "event",
						"fields": map[string]interface{}{
							"dataset": fmt.Sprintf("elastic_agent.%s", name),
						},
					},
				},
				{
					"add_fields": map[string]interface{}{
						"target": "elastic_agent",
						"fields": map[string]interface{}{
							"id":       agentID,
							"version":  version,
							"snapshot": isSnapshot,
						},
					},
				},
				{
					"add_fields": map[string]interface{}{
						"target": "agent",
						"fields": map[string]interface{}{
							"id": agentID,
						},
					},
				},
				{
					"drop_fields": map[string]interface{}{
						"fields": []string{
							"ecs.version", //coming from logger, already added by libbeat
						},
						"ignore_missing": true,
					},
				},
			},
		})
	}

	inputsNode, found := cfg[inputsKey]
	if !found {
		return fmt.Errorf("no inputs in config")
	}

	inputsCfg, ok := inputsNode.([]interface{})
	if !ok {
		return fmt.Errorf("inputs is not an array")
	}

	inputsCfg = append(inputsCfg, inputs...)
	cfg[inputsKey] = inputsCfg
	return nil
}

func (b *BeatsMonitor) monitoringNamespace() string {
	if ns := b.config.C.Namespace; ns != "" {
		return ns
	}
	return defaultMonitoringNamespace
}
func (b *BeatsMonitor) injectMetricsInput(cfg map[string]interface{}, units []string, monitoringOutputName string) error {
	monitoringNamespace := b.monitoringNamespace()
	fixedAgentName := strings.ReplaceAll(agentName, "-", "_")

	agentID := b.agentInfo.AgentID()
	version := b.agentInfo.Version()
	isSnapshot := b.agentInfo.Snapshot()

	inputs := []interface{}{
		map[string]interface{}{
			"type":       "http/metrics",
			idKey:        "metrics-monitoring-agent",
			useOutputKey: monitoringOutput,
			"metricsets": []string{"json"},
			"namespace":  "agent",
			"period":     "10s",
			"path":       "/stats",
			"hosts":      []string{b.agentMonitoringEndpoint()},
			"index":      fmt.Sprintf("metrics-elastic_agent.%s-%s", fixedAgentName, monitoringNamespace),
			"processors": []map[string]interface{}{
				{
					"add_fields": map[string]interface{}{
						"target": "data_stream",
						"fields": map[string]interface{}{
							"type":      "metrics",
							"dataset":   fmt.Sprintf("elastic_agent.%s", fixedAgentName),
							"namespace": monitoringNamespace,
						},
					},
				},
				{
					"add_fields": map[string]interface{}{
						"target": "event",
						"fields": map[string]interface{}{
							"dataset": fmt.Sprintf("elastic_agent.%s", fixedAgentName),
						},
					},
				},
				{
					"add_fields": map[string]interface{}{
						"target": "elastic_agent",
						"fields": map[string]interface{}{
							"id":       agentID,
							"version":  version,
							"snapshot": isSnapshot,
							"process":  "elastic-agent",
						},
					},
				},
				{
					"add_fields": map[string]interface{}{
						"target": "agent",
						"fields": map[string]interface{}{
							"id": agentID,
						},
					},
				},
				{
					"copy_fields": map[string]interface{}{
						"fields":         httpCopyRules(),
						"ignore_missing": true,
					},
				},
				{
					"drop_fields": map[string]interface{}{
						"fields": []string{
							"http",
						},
						"ignore_missing": true,
					},
				},
			},
		},
	}

	for _, unit := range units {
		name, isSupported := componentName(unit)
		if !isSupported {
			continue
		}
		endpoints := []string{endpointPath(unit, b.operatingSystem)}
		name = strings.ReplaceAll(name, "-", "_") // conform with index naming policy
		inputs = append(inputs, map[string]interface{}{
			"type":       "beat/metrics",
			idKey:        "metrics-monitoring-" + name,
			useOutputKey: monitoringOutput,
			"metricsets": []string{"stats", "state"},
			"period":     "10s",
			"hosts":      endpoints,
			"index":      fmt.Sprintf("metrics-elastic_agent.%s-%s", name, monitoringNamespace),
			"processors": []map[string]interface{}{
				{
					"add_fields": map[string]interface{}{
						"target": "data_stream",
						"fields": map[string]interface{}{
							"type":      "metrics",
							"dataset":   fmt.Sprintf("elastic_agent.%s", name),
							"namespace": monitoringNamespace,
						},
					},
				},
				{
					"add_fields": map[string]interface{}{
						"target": "event",
						"fields": map[string]interface{}{
							"dataset": fmt.Sprintf("elastic_agent.%s", name),
						},
					},
				},
				{
					"add_fields": map[string]interface{}{
						"target": "elastic_agent",
						"fields": map[string]interface{}{
							"id":       agentID,
							"version":  version,
							"snapshot": isSnapshot,
						},
					},
				},
				{
					"add_fields": map[string]interface{}{
						"target": "agent",
						"fields": map[string]interface{}{
							"id": agentID,
						},
					},
				},
			},
		}, map[string]interface{}{
			"type":       "http/metrics",
			useOutputKey: monitoringOutput,
			"metricsets": []string{"json"},
			"namespace":  "agent",
			"period":     "10s",
			"path":       "/stats",
			"hosts":      endpoints,
			"index":      fmt.Sprintf("metrics-elastic_agent.%s-%s", fixedAgentName, monitoringNamespace),
			"processors": []map[string]interface{}{
				{
					"add_fields": map[string]interface{}{
						"target": "data_stream",
						"fields": map[string]interface{}{
							"type":      "metrics",
							"dataset":   fmt.Sprintf("elastic_agent.%s", fixedAgentName),
							"namespace": monitoringNamespace,
						},
					},
				},
				{
					"add_fields": map[string]interface{}{
						"target": "event",
						"fields": map[string]interface{}{
							"dataset": fmt.Sprintf("elastic_agent.%s", fixedAgentName),
						},
					},
				},
				{
					"add_fields": map[string]interface{}{
						"target": "elastic_agent",
						"fields": map[string]interface{}{
							"id":       agentID,
							"version":  version,
							"snapshot": isSnapshot,
							"process":  name,
						},
					},
				},
				{
					"add_fields": map[string]interface{}{
						"target": "agent",
						"fields": map[string]interface{}{
							"id": agentID,
						},
					},
				},
				{
					"copy_fields": map[string]interface{}{
						"fields":         httpCopyRules(),
						"ignore_missing": true,
					},
				},
				{
					"drop_fields": map[string]interface{}{
						"fields": []string{
							"http",
						},
						"ignore_missing": true,
					},
				},
			},
		})
	}

	inputsNode, found := cfg[inputsKey]
	if !found {
		return fmt.Errorf("no inputs in config")
	}

	inputsCfg, ok := inputsNode.([]interface{})
	if !ok {
		return fmt.Errorf("inputs is not an array")
	}

	inputsCfg = append(inputsCfg, inputs...)
	cfg[inputsKey] = inputsCfg
	return nil
}

func loggingPath(id, operatingSystem string) string {
	if operatingSystem == windowsOS {
		return fmt.Sprintf(logFileFormatWin, paths.Home(), id)
	}

	return fmt.Sprintf(logFileFormat, paths.Home(), id)
}

func endpointPath(id, operatingSystem string) (endpointPath string) {
	if operatingSystem == windowsOS {
		return fmt.Sprintf(mbEndpointFileFormatWin, id)
	}
	// unix socket path must be less than 104 characters
	path := fmt.Sprintf("unix://%s.sock", filepath.Join(paths.TempDir(), id))
	if len(path) < 104 {
		return path
	}
	// place in global /tmp (or /var/tmp on Darwin) to ensure that its small enough to fit; current path is way to long
	// for it to be used, but needs to be unique per Agent (in the case that multiple are running)
	return fmt.Sprintf(`unix:///tmp/elastic-agent/%x.sock`, sha256.Sum256([]byte(path)))
}

func monitoringFile(id, operatingSystem string) string {
	endpoint := endpointPath(id, operatingSystem)
	if endpoint == "" {
		return ""
	}
	if isNpipe(endpoint) {
		return ""
	}

	if isWindowsPath(endpoint) {
		return endpoint
	}

	u, _ := url.Parse(endpoint)
	if u == nil || (u.Scheme != "" && u.Scheme != "file" && u.Scheme != "unix") {
		return ""
	}

	if u.Scheme == "file" {
		return strings.TrimPrefix(endpoint, "file://")
	}

	if u.Scheme == "unix" {
		return strings.TrimPrefix(endpoint, "unix://")
	}
	return endpoint
}

func isNpipe(path string) bool {
	return strings.HasPrefix(path, "npipe") || strings.HasPrefix(path, `\\.\pipe\`)
}

func isWindowsPath(path string) bool {
	if len(path) < 4 {
		return false
	}
	return unicode.IsLetter(rune(path[0])) && path[1] == ':'
}

func changeOwner(path string, uid, gid int) error {
	if runtime.GOOS == windowsOS {
		// on windows it always returns the syscall.EWINDOWS error, wrapped in *PathError
		return nil
	}

	return os.Chown(path, uid, gid)
}

func componentName(unit string) (string, bool) {
	for _, comp := range supportedComponents {
		if strings.HasPrefix(unit, comp) {
			return comp, true
		}
	}

	return "", false
}

func (b *BeatsMonitor) agentMonitoringEndpoint() string {
	if b.config.C != nil && b.config.C.Enabled {
		return httpPlusPrefix + fmt.Sprintf(agentMbEndpointHTTP, b.config.C.HTTP.Host, b.config.C.HTTP.Port)
	}

	if b.operatingSystem == windowsOS {
		return httpPlusPrefix + agentMbEndpointFileFormatWin
	}
	// unix socket path must be less than 104 characters
	path := fmt.Sprintf("unix://%s.sock", filepath.Join(paths.TempDir(), agentName))
	if len(path) < 104 {
		return httpPlusPrefix + path
	}
	// place in global /tmp to ensure that its small enough to fit; current path is way to long
	// for it to be used, but needs to be unique per Agent (in the case that multiple are running)
	return httpPlusPrefix + fmt.Sprintf(`unix:///tmp/elastic-agent/%x.sock`, sha256.Sum256([]byte(path)))
}

func httpCopyRules() []map[string]interface{} {
	fromToMap := []map[string]interface{}{
		// I should be able to see the CPU Usage on the running machine. Am using too much CPU?
		{
			"from": "http.agent.beat.cpu",
			"to":   "system.process.cpu",
		},
		// I should be able to see the Memory usage of Elastic Agent. Is the Elastic Agent using too much memory?
		{
			"from": "http.agent.beat.memstats.memory_sys",
			"to":   "system.process.memory.size",
		},
		// I should be able to see the system memory. Am I running out of memory?
		// TODO: with APM agent: total and free

		// I should be able to see Disk usage on the running machine. Am I running out of disk space?
		// TODO: with APM agent

		// I should be able to see fd usage. Am I keep too many files open?
		{
			"from": "http.agent.beat.handles",
			"to":   "system.process.fd",
		},
		// Cgroup reporting
		{
			"from": "http.agent.beat.cgroup",
			"to":   "system.process.cgroup",
		},

		// apm-server specific
		{
			"from": "http.agent.apm-server",
			"to":   "apm-server",
		},
	}

	return fromToMap
}
