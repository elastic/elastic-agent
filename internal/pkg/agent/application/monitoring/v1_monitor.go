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
	httpPrefix          = "http"
	fileSchemePrefix    = "file"
	unixSchemePrefix    = "unix"

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
	supportedComponents      = []string{"filebeat", "metricbeat", "apm-server", "auditbeat", "cloudbeat", "endpoint-security", "fleet-server", "heartbeat", "osquerybeat", "packetbeat"}
	supportedBeatsComponents = []string{"filebeat", "metricbeat", "auditbeat", "cloudbeat", "heartbeat", "osquerybeat", "packetbeat"}
)

// Beats monitor is providing V1 monitoring support.
type BeatsMonitor struct {
	enabled         bool // feature flag disabling whole v1 monitoring story
	config          *monitoringConfig
	operatingSystem string
	agentInfo       *info.AgentInfo
}

type monitoringConfig struct {
	C *monitoringCfg.MonitoringConfig `config:"agent.monitoring"`
}

// New creates a new BeatsMonitor instance.
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

// Reload refreshes monitoring configuration.
func (b *BeatsMonitor) Reload(rawConfig *config.Config) error {
	if !b.Enabled() {
		return nil
	}

	if err := rawConfig.Unpack(&b.config); err != nil {
		return errors.New(err, "failed to unpack monitoring config during reload")
	}
	return nil
}

// InjectMonitoring adds monitoring inputs to a configuration based on retrieved list of components to run.
func (b *BeatsMonitor) InjectMonitoring(cfg map[string]interface{}, componentIDToBinary map[string]string) error {
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
		if err := b.injectLogsInput(cfg, componentIDToBinary, monitoringOutput); err != nil {
			return errors.New(err, "failed to inject monitoring output")
		}
	}

	if b.config.C.MonitorMetrics {
		if err := b.injectMetricsInput(cfg, componentIDToBinary, monitoringOutput); err != nil {
			return errors.New(err, "failed to inject monitoring output")
		}
	}
	return nil
}

// EnrichArgs enriches arguments provided to application, in order to enable
// monitoring
func (b *BeatsMonitor) EnrichArgs(unit, binary string, args []string) []string {
	if !b.enabled {
		// even if monitoring is disabled enrich args.
		// the only way to skip it is by disabling monitoring by feature flag
		return args
	}

	// only beats understands these flags
	if !isSupportedBeatsBinary(binary) {
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
		metricsDrop := monitoringDrop(endpointPath("unit", b.operatingSystem))
		drops = append(drops, metricsDrop)
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

func (b *BeatsMonitor) injectLogsInput(cfg map[string]interface{}, componentIDToBinary map[string]string, monitoringOutput string) error {
	monitoringNamespace := b.monitoringNamespace()
	//fixedAgentName := strings.ReplaceAll(agentName, "-", "_")
	logsDrop := filepath.Dir(loggingPath("unit", b.operatingSystem))

	streams := []interface{}{
		map[string]interface{}{
			idKey: "logs-monitoring-agent",
			"data_stream": map[string]interface{}{
				"type":      "logs",
				"dataset":   "elastic_agent",
				"namespace": monitoringNamespace,
			},
			"paths": []interface{}{
				filepath.Join(logsDrop, agentName+"-*.ndjson"),
				filepath.Join(logsDrop, agentName+"-watcher-*.ndjson"),
			},
			"index": fmt.Sprintf("logs-elastic_agent-%s", monitoringNamespace),
			"close": map[string]interface{}{
				"on_state_change": map[string]interface{}{
					"inactive": "5m",
				},
			},
			"parsers": []interface{}{
				map[string]interface{}{
					"ndjson": map[string]interface{}{
						"overwrite_keys": true,
						"message_key":    "message",
					},
				},
			},
			"processors": []interface{}{
				map[string]interface{}{
					"add_fields": map[string]interface{}{
						"target": "data_stream",
						"fields": map[string]interface{}{
							"type":      "logs",
							"dataset":   "elastic_agent",
							"namespace": monitoringNamespace,
						},
					},
				},
				map[string]interface{}{
					"add_fields": map[string]interface{}{
						"target": "event",
						"fields": map[string]interface{}{
							"dataset": "elastic_agent",
						},
					},
				},
				map[string]interface{}{
					"add_fields": map[string]interface{}{
						"target": "elastic_agent",
						"fields": map[string]interface{}{
							"id":       b.agentInfo.AgentID(),
							"version":  b.agentInfo.Version(),
							"snapshot": b.agentInfo.Snapshot(),
						},
					},
				},
				map[string]interface{}{
					"add_fields": map[string]interface{}{
						"target": "agent",
						"fields": map[string]interface{}{
							"id": b.agentInfo.AgentID(),
						},
					},
				},
				map[string]interface{}{
					"drop_fields": map[string]interface{}{
						"fields": []interface{}{
							"ecs.version", //coming from logger, already added by libbeat
						},
						"ignore_missing": true,
					},
				}},
		},
	}
	for unit, binaryName := range componentIDToBinary {
		if !isSupportedBinary(binaryName) {
			continue
		}

		fixedBinaryName := strings.ReplaceAll(binaryName, "-", "_")
		name := strings.ReplaceAll(unit, "-", "_") // conform with index naming policy
		logFile := loggingPath(unit, b.operatingSystem)
		streams = append(streams, map[string]interface{}{
			idKey: "logs-monitoring-" + name,
			"data_stream": map[string]interface{}{
				"type":      "logs",
				"dataset":   fmt.Sprintf("elastic_agent.%s", fixedBinaryName),
				"namespace": monitoringNamespace,
			},
			"index": fmt.Sprintf("logs-elastic_agent.%s-%s", fixedBinaryName, monitoringNamespace),
			"paths": []interface{}{logFile, logFile + "*"},
			"close": map[string]interface{}{
				"on_state_change": map[string]interface{}{
					"inactive": "5m",
				},
			},
			"parsers": []interface{}{
				map[string]interface{}{
					"ndjson": map[string]interface{}{
						"overwrite_keys": true,
						"message_key":    "message",
					},
				},
			},
			"processors": []interface{}{
				map[string]interface{}{
					"add_fields": map[string]interface{}{
						"target": "data_stream",
						"fields": map[string]interface{}{
							"type":      "logs",
							"dataset":   fmt.Sprintf("elastic_agent.%s", fixedBinaryName),
							"namespace": monitoringNamespace,
						},
					},
				},
				map[string]interface{}{
					"add_fields": map[string]interface{}{
						"target": "event",
						"fields": map[string]interface{}{
							"dataset": fmt.Sprintf("elastic_agent.%s", fixedBinaryName),
						},
					},
				},
				map[string]interface{}{
					"add_fields": map[string]interface{}{
						"target": "elastic_agent",
						"fields": map[string]interface{}{
							"id":       b.agentInfo.AgentID(),
							"version":  b.agentInfo.Version(),
							"snapshot": b.agentInfo.Snapshot(),
						},
					},
				},
				map[string]interface{}{
					"add_fields": map[string]interface{}{
						"target": "agent",
						"fields": map[string]interface{}{
							"id": b.agentInfo.AgentID(),
						},
					},
				},
				map[string]interface{}{
					"drop_fields": map[string]interface{}{
						"fields": []interface{}{
							"ecs.version", //coming from logger, already added by libbeat
						},
						"ignore_missing": true,
					},
				},
			},
		})
	}

	inputs := []interface{}{
		map[string]interface{}{
			idKey:        "logs-monitoring-agent",
			"name":       "logs-monitoring-agent",
			"type":       "filestream",
			useOutputKey: monitoringOutput,
			"data_stream": map[string]interface{}{
				"namespace": monitoringNamespace,
			},
			"streams": streams,
		},
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
func (b *BeatsMonitor) injectMetricsInput(cfg map[string]interface{}, componentIDToBinary map[string]string, monitoringOutputName string) error {
	monitoringNamespace := b.monitoringNamespace()
	fixedAgentName := strings.ReplaceAll(agentName, "-", "_")
	beatsStreams := make([]interface{}, 0, len(componentIDToBinary))
	streams := []interface{}{
		map[string]interface{}{
			idKey: "metrics-monitoring-agent",
			"data_stream": map[string]interface{}{
				"type":      "metrics",
				"dataset":   fmt.Sprintf("elastic_agent.%s", fixedAgentName),
				"namespace": monitoringNamespace,
			},
			"metricsets": []interface{}{"json"},
			"path":       "/stats",
			"hosts":      []interface{}{HttpPlusAgentMonitoringEndpoint(b.operatingSystem, b.config.C)},
			"namespace":  "agent",
			"period":     "10s",
			"index":      fmt.Sprintf("metrics-elastic_agent.%s-%s", fixedAgentName, monitoringNamespace),
			"processors": []interface{}{
				map[string]interface{}{
					"add_fields": map[string]interface{}{
						"target": "data_stream",
						"fields": map[string]interface{}{
							"type":      "metrics",
							"dataset":   fmt.Sprintf("elastic_agent.%s", fixedAgentName),
							"namespace": monitoringNamespace,
						},
					},
				},
				map[string]interface{}{
					"add_fields": map[string]interface{}{
						"target": "event",
						"fields": map[string]interface{}{
							"dataset": fmt.Sprintf("elastic_agent.%s", fixedAgentName),
						},
					},
				},
				map[string]interface{}{
					"add_fields": map[string]interface{}{
						"target": "elastic_agent",
						"fields": map[string]interface{}{
							"id":       b.agentInfo.AgentID(),
							"version":  b.agentInfo.Version(),
							"snapshot": b.agentInfo.Snapshot(),
							"process":  "elastic-agent",
						},
					},
				},
				map[string]interface{}{
					"add_fields": map[string]interface{}{
						"target": "agent",
						"fields": map[string]interface{}{
							"id": b.agentInfo.AgentID(),
						},
					},
				},
				map[string]interface{}{
					"copy_fields": map[string]interface{}{
						"fields":         httpCopyRules(),
						"ignore_missing": true,
						"fail_on_error":  false,
					},
				},
				map[string]interface{}{
					"drop_fields": map[string]interface{}{
						"fields": []interface{}{
							"http",
						},
						"ignore_missing": true,
					},
				},
			},
		},
	}
	for unit, binaryName := range componentIDToBinary {
		if !isSupportedBinary(binaryName) {
			continue
		}

		endpoints := []interface{}{prefixedEndpoint(endpointPath(unit, b.operatingSystem))}
		name := strings.ReplaceAll(unit, "-", "_") // conform with index naming policy

		if isSupportedBeatsBinary(binaryName) {
			beatsStreams = append(beatsStreams, map[string]interface{}{
				idKey: "metrics-monitoring-" + name,
				"data_stream": map[string]interface{}{
					"type":      "metrics",
					"dataset":   fmt.Sprintf("elastic_agent.%s", name),
					"namespace": monitoringNamespace,
				},
				"metricsets": []interface{}{"stats", "state"},
				"hosts":      endpoints,
				"period":     "10s",
				"index":      fmt.Sprintf("metrics-elastic_agent.%s-%s", fixedAgentName, monitoringNamespace),
				"processors": []interface{}{
					map[string]interface{}{
						"add_fields": map[string]interface{}{
							"target": "data_stream",
							"fields": map[string]interface{}{
								"type":      "metrics",
								"dataset":   fmt.Sprintf("elastic_agent.%s", name),
								"namespace": monitoringNamespace,
							},
						},
					},
					map[string]interface{}{
						"add_fields": map[string]interface{}{
							"target": "event",
							"fields": map[string]interface{}{
								"dataset": fmt.Sprintf("elastic_agent.%s", name),
							},
						},
					},
					map[string]interface{}{
						"add_fields": map[string]interface{}{
							"target": "elastic_agent",
							"fields": map[string]interface{}{
								"id":       b.agentInfo.AgentID(),
								"version":  b.agentInfo.Version(),
								"snapshot": b.agentInfo.Snapshot(),
								"process":  binaryName,
							},
						},
					},
					map[string]interface{}{
						"add_fields": map[string]interface{}{
							"target": "agent",
							"fields": map[string]interface{}{
								"id": b.agentInfo.AgentID(),
							},
						},
					},
				},
			})
		}

		streams = append(streams, map[string]interface{}{
			idKey: "metrics-monitoring-" + name + "-1",
			"data_stream": map[string]interface{}{
				"type":      "metrics",
				"dataset":   fmt.Sprintf("elastic_agent.%s", fixedAgentName),
				"namespace": monitoringNamespace,
			},
			"metricsets": []interface{}{"json"},
			"hosts":      endpoints,
			"path":       "/stats",
			"namespace":  "agent",
			"period":     "10s",
			"index":      fmt.Sprintf("metrics-elastic_agent.%s-%s", fixedAgentName, monitoringNamespace),
			"processors": []interface{}{
				map[string]interface{}{
					"add_fields": map[string]interface{}{
						"target": "event",
						"fields": map[string]interface{}{
							"dataset": fmt.Sprintf("elastic_agent.%s", fixedAgentName),
						},
					},
				},
				map[string]interface{}{
					"add_fields": map[string]interface{}{
						"target": "elastic_agent",
						"fields": map[string]interface{}{
							"id":       b.agentInfo.AgentID(),
							"version":  b.agentInfo.Version(),
							"snapshot": b.agentInfo.Snapshot(),
							"process":  name,
						},
					},
				},
				map[string]interface{}{
					"add_fields": map[string]interface{}{
						"target": "agent",
						"fields": map[string]interface{}{
							"id": b.agentInfo.AgentID(),
						},
					},
				},
				map[string]interface{}{
					"copy_fields": map[string]interface{}{
						"fields":         httpCopyRules(),
						"ignore_missing": true,
						"fail_on_error":  false,
					},
				},
				map[string]interface{}{
					"drop_fields": map[string]interface{}{
						"fields": []interface{}{
							"http",
						},
						"ignore_missing": true,
					},
				},
			},
		})
	}

	inputs := []interface{}{
		map[string]interface{}{
			idKey:        "metrics-monitoring-beats",
			"name":       "metrics-monitoring-beats",
			"type":       "beat/metrics",
			useOutputKey: monitoringOutput,
			"data_stream": map[string]interface{}{
				"namespace": monitoringNamespace,
			},
			"streams": beatsStreams,
		},
		map[string]interface{}{
			idKey:        "metrics-monitoring-agent",
			"name":       "metrics-monitoring-agent",
			"type":       "http/metrics",
			useOutputKey: monitoringOutput,
			"data_stream": map[string]interface{}{
				"namespace": monitoringNamespace,
			},
			"streams": streams,
		},
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
	id = strings.ReplaceAll(id, string(filepath.Separator), "-")
	if operatingSystem == windowsOS {
		return fmt.Sprintf(logFileFormatWin, paths.Home(), id)
	}

	return fmt.Sprintf(logFileFormat, paths.Home(), id)
}

func endpointPath(id, operatingSystem string) (endpointPath string) {
	id = strings.ReplaceAll(id, string(filepath.Separator), "-")
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

func prefixedEndpoint(endpoint string) string {
	if endpoint == "" || strings.HasPrefix(endpoint, httpPlusPrefix) || strings.HasPrefix(endpoint, httpPrefix) {
		return endpoint
	}

	return httpPlusPrefix + endpoint
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
	if u == nil || (u.Scheme != "" && u.Scheme != fileSchemePrefix && u.Scheme != unixSchemePrefix) {
		return ""
	}

	if u.Scheme == fileSchemePrefix {
		return strings.TrimPrefix(endpoint, "file://")
	}

	if u.Scheme == unixSchemePrefix {
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

// HttpPlusAgentMonitoringEndpoint provides an agent monitoring endpoint path with a `http+` prefix.
func HttpPlusAgentMonitoringEndpoint(operatingSystem string, cfg *monitoringCfg.MonitoringConfig) string {
	return prefixedEndpoint(AgentMonitoringEndpoint(operatingSystem, cfg))
}

// AgentMonitoringEndpoint provides an agent monitoring endpoint path.
func AgentMonitoringEndpoint(operatingSystem string, cfg *monitoringCfg.MonitoringConfig) string {
	if cfg != nil && cfg.Enabled {
		return fmt.Sprintf(agentMbEndpointHTTP, cfg.HTTP.Host, cfg.HTTP.Port)
	}

	if operatingSystem == windowsOS {
		return agentMbEndpointFileFormatWin
	}
	// unix socket path must be less than 104 characters
	path := fmt.Sprintf("unix://%s.sock", filepath.Join(paths.TempDir(), agentName))
	if len(path) < 104 {
		return path
	}
	// place in global /tmp to ensure that its small enough to fit; current path is way to long
	// for it to be used, but needs to be unique per Agent (in the case that multiple are running)
	return fmt.Sprintf(`unix:///tmp/elastic-agent/%x.sock`, sha256.Sum256([]byte(path)))
}

func httpCopyRules() []interface{} {
	fromToMap := []interface{}{
		// I should be able to see the CPU Usage on the running machine. Am using too much CPU?
		map[string]interface{}{
			"from": "http.agent.beat.cpu",
			"to":   "system.process.cpu",
		},

		// I should be able to see the Memory usage of Elastic Agent. Is the Elastic Agent using too much memory?
		map[string]interface{}{
			"from": "http.agent.beat.memstats.memory_sys",
			"to":   "system.process.memory.size",
		},

		// I should be able to see fd usage. Am I keep too many files open?
		map[string]interface{}{
			"from": "http.agent.beat.handles",
			"to":   "system.process.fd",
		},

		// Cgroup reporting
		map[string]interface{}{
			"from": "http.agent.beat.cgroup",
			"to":   "system.process.cgroup",
		},

		// apm-server specific
		map[string]interface{}{
			"from": "http.agent.apm-server",
			"to":   "apm-server",
		},
	}

	return fromToMap
}

func isSupportedBinary(binaryName string) bool {
	for _, supportedBinary := range supportedComponents {
		if strings.EqualFold(supportedBinary, binaryName) {
			return true
		}
	}
	return false
}

func isSupportedBeatsBinary(binaryName string) bool {
	for _, supportedBinary := range supportedBeatsComponents {
		if strings.EqualFold(supportedBinary, binaryName) {
			return true
		}
	}
	return false
}

func monitoringDrop(path string) (drop string) {
	defer func() {
		if drop != "" {
			// Dir call changes separator to the one used in OS
			// '/var/lib' -> '\var\lib\' on windows
			baseLen := len(filepath.Dir(drop))
			drop = drop[:baseLen]
		}
	}()

	if strings.Contains(path, "localhost") {
		return ""
	}

	path = strings.TrimPrefix(path, httpPlusPrefix)

	// npipe is virtual without a drop
	if isNpipe(path) {
		return ""
	}

	if isWindowsPath(path) {
		return path
	}

	u, _ := url.Parse(path)
	if u == nil || (u.Scheme != "" && u.Scheme != fileSchemePrefix && u.Scheme != unixSchemePrefix) {
		return ""
	}

	if u.Scheme == fileSchemePrefix {
		return strings.TrimPrefix(path, "file://")
	}

	if u.Scheme == unixSchemePrefix {
		return strings.TrimPrefix(path, "unix://")
	}

	return path
}
