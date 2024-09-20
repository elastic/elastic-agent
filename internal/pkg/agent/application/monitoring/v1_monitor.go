// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package monitoring

import (
	"crypto/sha256"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
	"unicode"

	"github.com/elastic/elastic-agent/pkg/component"
	"github.com/elastic/elastic-agent/pkg/utils"

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
	monitoringMetricsPeriodKey = "metrics_period"
	monitoringOutput           = "monitoring"
	defaultMonitoringNamespace = "default"
	agentName                  = "elastic-agent"

	monitoringMetricsUnitID = "metrics-monitoring"
	monitoringFilesUnitsID  = "filestream-monitoring"

	windowsOS = "windows"

	// metricset execution period used for the monitoring metrics inputs
	// we set this to 60s to reduce the load/data volume on the monitoring cluster
	defaultMetricsCollectionInterval = 60 * time.Second
)

var (
	errNoOuputPresent          = errors.New("outputs not part of the config")
	supportedMetricsComponents = []string{"filebeat", "metricbeat", "apm-server", "auditbeat", "cloudbeat", "fleet-server", "heartbeat", "osquerybeat", "packetbeat", "pf-elastic-collector", "pf-elastic-symbolizer"}
	supportedBeatsComponents   = []string{"filebeat", "metricbeat", "apm-server", "fleet-server", "auditbeat", "cloudbeat", "heartbeat", "osquerybeat", "packetbeat", "pf-elastic-collector", "pf-elastic-symbolizer"}
)

// BeatsMonitor provides config values for monitoring of agent clients (beats, endpoint, etc)
// by injecting the monitoring config into an existing fleet config
type BeatsMonitor struct {
	enabled         bool // feature flag disabling whole v1 monitoring story
	config          *monitoringConfig
	operatingSystem string
	agentInfo       info.Agent
}

type monitoringConfig struct {
	C *monitoringCfg.MonitoringConfig `config:"agent.monitoring"`
}

// New creates a new BeatsMonitor instance.
func New(enabled bool, operatingSystem string, cfg *monitoringCfg.MonitoringConfig, agentInfo info.Agent) *BeatsMonitor {
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
	if !b.enabled {
		// it's disabled regardless of config
		return nil
	}

	if err := rawConfig.Unpack(&b.config); err != nil {
		return errors.New(err, "failed to unpack monitoring config during reload")
	}
	return nil
}

// MonitoringConfig adds monitoring inputs to a configuration based on retrieved list of components to run.
// args:
// policy: the existing config policy
// components: a list of the expected running components
// componentIDToBinary: a map of component IDs to binary names
// componentIDPidMap: a map of component IDs to the PIDs of the running components.
func (b *BeatsMonitor) MonitoringConfig(
	policy map[string]interface{},
	components []component.Component,
	componentIDToBinary map[string]string,
	componentIDPidMap map[string]uint64,
) (map[string]interface{}, error) {
	if !b.Enabled() {
		return nil, nil
	}

	cfg := make(map[string]interface{})

	monitoringOutputName := defaultOutputName
	metricsCollectionIntervalString := b.config.C.MetricsPeriod
	if agentCfg, found := policy[agentKey]; found {
		// The agent section is required for feature flags
		cfg[agentKey] = agentCfg

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

					if metricsPeriod, found := monitoringMap[monitoringMetricsPeriodKey]; found {
						if metricsPeriodStr, ok := metricsPeriod.(string); ok {
							metricsCollectionIntervalString = metricsPeriodStr
						}
					}
				}
			}
		}
	}

	if err := b.injectMonitoringOutput(policy, cfg, monitoringOutputName); err != nil && !errors.Is(err, errNoOuputPresent) {
		return nil, errors.New(err, "failed to inject monitoring output")
	} else if errors.Is(err, errNoOuputPresent) {
		// nothing to inject, no monitoring output
		return nil, nil
	}

	// initializes inputs collection so injectors don't have to deal with it
	b.initInputs(cfg)

	if b.config.C.MonitorLogs {
		if err := b.injectLogsInput(cfg, components, monitoringOutput); err != nil {
			return nil, errors.New(err, "failed to inject monitoring output")
		}
	}

	if b.config.C.MonitorMetrics {
		if err := b.injectMetricsInput(cfg, componentIDToBinary, components, componentIDPidMap, metricsCollectionIntervalString); err != nil {
			return nil, errors.New(err, "failed to inject monitoring output")
		}
	}
	return cfg, nil
}

// EnrichArgs enriches arguments provided to application, in order to enable
// monitoring
func (b *BeatsMonitor) EnrichArgs(unit, binary string, args []string) []string {
	if !b.enabled {
		// even if monitoring is disabled enrich args.
		// the only way to skip it is by disabling monitoring by feature flag
		return args
	}

	// only beats understand these flags
	if !isSupportedBeatsBinary(binary) {
		return args
	}

	appendix := make([]string, 0, 20)
	endpoint := utils.SocketURLWithFallback(unit, paths.TempDir())
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

	if !b.config.C.LogMetrics {
		appendix = append(appendix,
			"-E", "logging.metrics.enabled=false",
		)
	}

	return append(args, appendix...)
}

// Prepare executes steps in order for monitoring to work correctly
func (b *BeatsMonitor) Prepare(unit string) error {
	if !b.Enabled() {
		return nil
	}
	drops := make([]string, 0, 2)
	if b.config.C.MonitorLogs {
		logsDrop := loggingPath(unit, b.operatingSystem)
		drops = append(drops, filepath.Dir(logsDrop))
	}

	if b.config.C.MonitorMetrics {
		metricsDrop := monitoringDrop(utils.SocketURLWithFallback(unit, paths.TempDir()))
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
			if err := os.MkdirAll(drop, 0o775); err != nil {
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

	endpoint := monitoringFile(unit)
	if endpoint == "" {
		return nil
	}

	return os.RemoveAll(endpoint)
}

func (b *BeatsMonitor) initInputs(cfg map[string]interface{}) {
	_, found := cfg[inputsKey]
	if found {
		return
	}

	inputsCollection := make([]interface{}, 0)
	cfg[inputsKey] = inputsCollection
}

func (b *BeatsMonitor) injectMonitoringOutput(source, dest map[string]interface{}, monitoringOutputName string) error {
	outputsNode, found := source[outputsKey]
	if !found {
		return errNoOuputPresent
	}

	outputs, ok := outputsNode.(map[string]interface{})
	if !ok {
		return fmt.Errorf("outputs not a map")
	}

	outputNode, found := outputs[monitoringOutputName]
	if !found {
		return fmt.Errorf("output %q used for monitoring not found", monitoringOutputName)
	}

	monitoringOutputs := map[string]interface{}{
		monitoringOutput: outputNode,
	}

	dest[outputsKey] = monitoringOutputs

	return nil
}

// injectLogsInput adds logging configs for component monitoring to the `cfg` map
func (b *BeatsMonitor) injectLogsInput(cfg map[string]interface{}, components []component.Component, monitoringOutput string) error {
	monitoringNamespace := b.monitoringNamespace()
	logsDrop := filepath.Dir(loggingPath("unit", b.operatingSystem))

	streams := []interface{}{
		map[string]interface{}{
			idKey:  fmt.Sprintf("%s-agent", monitoringFilesUnitsID),
			"type": "filestream",
			"paths": []interface{}{
				filepath.Join(logsDrop, agentName+"-*.ndjson"),
				filepath.Join(logsDrop, agentName+"-watcher-*.ndjson"),
			},
			"data_stream": map[string]interface{}{
				"type":      "logs",
				"dataset":   "elastic_agent",
				"namespace": monitoringNamespace,
			},
			"close": map[string]interface{}{
				"on_state_change": map[string]interface{}{
					"inactive": "5m",
				},
			},
			"parsers": []interface{}{
				map[string]interface{}{
					"ndjson": map[string]interface{}{
						"message_key":    "message",
						"overwrite_keys": true,
						"add_error_key":  true,
						"target":         "",
					},
				},
			},
			"processors": []any{
				// drop all events from monitoring components (do it early)
				// without dropping these events the filestream gets stuck in an infinite loop
				// if filestream hits an issue publishing the events it logs an error which then filestream monitor
				// will read from the logs and try to also publish that new log message (thus the infinite loop).
				// The only way to identify a monitoring component by looking
				// at their ID. They all end in `-monitoring`, e.g:
				// - "beat/metrics-monitoring"
				// - "filestream-monitoring"
				// - "http/metrics-monitoring"
				map[string]interface{}{
					"drop_event": map[string]interface{}{
						"when": map[string]interface{}{
							"regexp": map[string]interface{}{
								"component.id": ".*-monitoring$",
							},
						},
					},
				},
				// drop periodic metrics logs (those are useful mostly in diagnostic dumps where we collect log files)
				map[string]interface{}{
					"drop_event": map[string]interface{}{
						"when": map[string]interface{}{
							"regexp": map[string]interface{}{
								"message": "^Non-zero metrics in the last",
							},
						},
					},
				},
				// copy original dataset so we can drop the dataset field
				map[string]interface{}{
					"copy_fields": map[string]interface{}{
						"fields": []interface{}{
							map[string]interface{}{
								"from": "data_stream.dataset",
								"to":   "data_stream.dataset_original",
							},
						},
					},
				},
				// drop the dataset field so following copy_field can copy to it
				map[string]interface{}{
					"drop_fields": map[string]interface{}{
						"fields": []interface{}{
							"data_stream.dataset",
						},
					},
				},
				// copy component.dataset as the real dataset
				map[string]interface{}{
					"copy_fields": map[string]interface{}{
						"fields": []interface{}{
							map[string]interface{}{
								"from": "component.dataset",
								"to":   "data_stream.dataset",
							},
						},
						"fail_on_error":  false,
						"ignore_missing": true,
					},
				},
				// possible it's a log message from agent itself (doesn't have component.dataset)
				map[string]interface{}{
					"copy_fields": map[string]interface{}{
						"fields": []interface{}{
							map[string]interface{}{
								"from": "data_stream.dataset_original",
								"to":   "data_stream.dataset",
							},
						},
						"fail_on_error": false,
					},
				},
				// drop the original dataset copied and the event.dataset (as it will be updated)
				map[string]interface{}{
					"drop_fields": map[string]interface{}{
						"fields": []interface{}{
							"data_stream.dataset_original",
							"event.dataset",
						},
					},
				},
				// update event.dataset with the now used data_stream.dataset
				map[string]interface{}{
					"copy_fields": map[string]interface{}{
						"fields": []interface{}{
							map[string]interface{}{
								"from": "data_stream.dataset",
								"to":   "event.dataset",
							},
						},
					},
				},
				// coming from logger, added by agent (drop)
				map[string]interface{}{
					"drop_fields": map[string]interface{}{
						"fields": []interface{}{
							"ecs.version",
						},
						"ignore_missing": true,
					},
				},
				// adjust destination data_stream based on the data_stream fields
				map[string]interface{}{
					"add_formatted_index": map[string]interface{}{
						"index": "%{[data_stream.type]}-%{[data_stream.dataset]}-%{[data_stream.namespace]}",
					},
				},
			},
		},
	}

	// service components that define a log path are monitored using its own stream in the monitor
	for _, comp := range components {
		if comp.InputSpec == nil || comp.InputSpec.Spec.Service == nil || comp.InputSpec.Spec.Service.Log == nil || comp.InputSpec.Spec.Service.Log.Path == "" {
			// only monitor service inputs that define a log path
			continue
		}
		fixedBinaryName := strings.ReplaceAll(strings.ReplaceAll(comp.BinaryName(), "-", "_"), "/", "_") // conform with index naming policy
		dataset := fmt.Sprintf("elastic_agent.%s", fixedBinaryName)
		streams = append(streams, map[string]interface{}{
			idKey:  fmt.Sprintf("%s-%s", monitoringFilesUnitsID, comp.ID),
			"type": "filestream",
			"paths": []interface{}{
				comp.InputSpec.Spec.Service.Log.Path,
			},
			"data_stream": map[string]interface{}{
				"type":      "logs",
				"dataset":   dataset,
				"namespace": monitoringNamespace,
			},
			"close": map[string]interface{}{
				"on_state_change": map[string]interface{}{
					"inactive": "5m",
				},
			},
			"parsers": []interface{}{
				map[string]interface{}{
					"ndjson": map[string]interface{}{
						"message_key":    "message",
						"overwrite_keys": true,
						"add_error_key":  true,
						"target":         "",
					},
				},
			},
			"processors": []interface{}{
				map[string]interface{}{
					// component information must be injected because it's not a subprocess
					"add_fields": map[string]interface{}{
						"target": "component",
						"fields": map[string]interface{}{
							"id":      comp.ID,
							"type":    comp.InputSpec.InputType,
							"binary":  comp.BinaryName(),
							"dataset": dataset,
						},
					},
				},
				map[string]interface{}{
					// injecting component log source to stay aligned with command runtime logs
					"add_fields": map[string]interface{}{
						"target": "log",
						"fields": map[string]interface{}{
							"source": comp.ID,
						},
					},
				},
			},
		})
	}

	inputs := []interface{}{
		map[string]interface{}{
			idKey:        fmt.Sprintf("%s-agent", monitoringFilesUnitsID),
			"name":       fmt.Sprintf("%s-agent", monitoringFilesUnitsID),
			"type":       "filestream",
			useOutputKey: monitoringOutput,
			"streams":    streams,
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

// injectMetricsInput injects monitoring config for agent monitoring to the `cfg` object.
func (b *BeatsMonitor) injectMetricsInput(
	cfg map[string]interface{},
	componentIDToBinary map[string]string,
	componentList []component.Component,
	existingStateServicePids map[string]uint64,
	metricsCollectionIntervalString string,
) error {
	if metricsCollectionIntervalString == "" {
		metricsCollectionIntervalString = defaultMetricsCollectionInterval.String()
	}
	monitoringNamespace := b.monitoringNamespace()
	fixedAgentName := strings.ReplaceAll(agentName, "-", "_")
	beatsStreams := make([]interface{}, 0, len(componentIDToBinary))
	streams := []interface{}{
		map[string]interface{}{
			idKey: fmt.Sprintf("%s-agent", monitoringMetricsUnitID),
			"data_stream": map[string]interface{}{
				"type":      "metrics",
				"dataset":   fmt.Sprintf("elastic_agent.%s", fixedAgentName),
				"namespace": monitoringNamespace,
			},
			"metricsets": []interface{}{"json"},
			"path":       "/stats",
			"hosts":      []interface{}{HttpPlusAgentMonitoringEndpoint(b.operatingSystem, b.config.C)},
			"namespace":  "agent",
			"period":     metricsCollectionIntervalString,
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
				map[string]interface{}{
					"add_fields": map[string]interface{}{
						"target": "component",
						"fields": map[string]interface{}{
							"id":     "elastic-agent",
							"binary": "elastic-agent",
						},
					},
				},
			},
		},
	}

	//create a new map with the monitoring beats included
	componentListWithMonitoring := map[string]string{
		fmt.Sprintf("beat/%s", monitoringMetricsUnitID): "metricbeat",
		fmt.Sprintf("http/%s", monitoringMetricsUnitID): "metricbeat",
		monitoringFilesUnitsID:                          "filebeat",
	}
	for k, v := range componentIDToBinary {
		componentListWithMonitoring[k] = v
	}

	for unit, binaryName := range componentListWithMonitoring {
		if !isSupportedMetricsBinary(binaryName) {
			continue
		}

		endpoints := []interface{}{prefixedEndpoint(utils.SocketURLWithFallback(unit, paths.TempDir()))}
		name := strings.ReplaceAll(strings.ReplaceAll(binaryName, "-", "_"), "/", "_") // conform with index naming policy

		if isSupportedBeatsBinary(binaryName) {
			beatsStreams = append(beatsStreams, map[string]interface{}{
				idKey: fmt.Sprintf("%s-", monitoringMetricsUnitID) + name,
				"data_stream": map[string]interface{}{
					"type":      "metrics",
					"dataset":   fmt.Sprintf("elastic_agent.%s", name),
					"namespace": monitoringNamespace,
				},
				"metricsets": []interface{}{"stats"},
				"hosts":      endpoints,
				"period":     metricsCollectionIntervalString,
				"index":      fmt.Sprintf("metrics-elastic_agent.%s-%s", name, monitoringNamespace),
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
					map[string]interface{}{
						"add_fields": map[string]interface{}{
							"target": "component",
							"fields": map[string]interface{}{
								"id":     unit,
								"binary": binaryName,
							},
						},
					},
				},
			})
		}

		streams = append(streams, map[string]interface{}{
			idKey: fmt.Sprintf("%s-%s-1", monitoringMetricsUnitID, name),
			"data_stream": map[string]interface{}{
				"type":      "metrics",
				"dataset":   fmt.Sprintf("elastic_agent.%s", fixedAgentName),
				"namespace": monitoringNamespace,
			},
			"metricsets": []interface{}{"json"},
			"hosts":      endpoints,
			"path":       "/stats",
			"namespace":  "agent",
			"period":     metricsCollectionIntervalString,
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
				map[string]interface{}{
					"add_fields": map[string]interface{}{
						"target": "component",
						"fields": map[string]interface{}{
							"id":     unit,
							"binary": binaryName,
						},
					},
				},
			},
		})

		if strings.EqualFold(name, "filebeat") {
			fbDataStreamName := "filebeat_input"
			streams = append(streams, map[string]interface{}{
				idKey: fmt.Sprintf("%s-%s-1", monitoringMetricsUnitID, name),
				"data_stream": map[string]interface{}{
					"type":      "metrics",
					"dataset":   fmt.Sprintf("elastic_agent.%s", fbDataStreamName),
					"namespace": monitoringNamespace,
				},
				"metricsets":    []interface{}{"json"},
				"hosts":         endpoints,
				"path":          "/inputs/",
				"namespace":     fbDataStreamName,
				"json.is_array": true,
				"period":        metricsCollectionIntervalString,
				"index":         fmt.Sprintf("metrics-elastic_agent.%s-%s", fbDataStreamName, monitoringNamespace),
				"processors": []interface{}{
					map[string]interface{}{
						"add_fields": map[string]interface{}{
							"target": "event",
							"fields": map[string]interface{}{
								"dataset": fmt.Sprintf("elastic_agent.%s", fbDataStreamName),
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
					map[string]interface{}{
						"add_fields": map[string]interface{}{
							"target": "component",
							"fields": map[string]interface{}{
								"id":     unit,
								"binary": binaryName,
							},
						},
					},
				},
			})
		}

	}

	inputs := []interface{}{
		map[string]interface{}{
			idKey:        fmt.Sprintf("%s-beats", monitoringMetricsUnitID),
			"name":       fmt.Sprintf("%s-beats", monitoringMetricsUnitID),
			"type":       "beat/metrics",
			useOutputKey: monitoringOutput,
			"data_stream": map[string]interface{}{
				"namespace": monitoringNamespace,
			},
			"streams": beatsStreams,
		},
		map[string]interface{}{
			idKey:        fmt.Sprintf("%s-agent", monitoringMetricsUnitID),
			"name":       fmt.Sprintf("%s-agent", monitoringMetricsUnitID),
			"type":       "http/metrics",
			useOutputKey: monitoringOutput,
			"data_stream": map[string]interface{}{
				"namespace": monitoringNamespace,
			},
			"streams": streams,
		},
	}

	// add system/process metrics for services that can't be monitored via json/beats metrics
	// If there's a checkin PID and the corresponding component has a service spec section, add a system/process config
	for _, compState := range componentList {
		if compState.InputSpec != nil && compState.InputSpec.Spec.Service != nil {
			if comp, ok := existingStateServicePids[compState.ID]; ok && comp != 0 {
				name := strings.ReplaceAll(strings.ReplaceAll(compState.BinaryName(), "-", "_"), "/", "_")
				inputs = append(inputs, map[string]interface{}{
					idKey:        fmt.Sprintf("%s-%s", monitoringMetricsUnitID, name),
					"name":       fmt.Sprintf("%s-%s", monitoringMetricsUnitID, name),
					"type":       "system/metrics",
					useOutputKey: monitoringOutput,
					"data_stream": map[string]interface{}{
						"namespace": monitoringNamespace,
					},
					"streams": []interface{}{
						map[string]interface{}{
							idKey: fmt.Sprintf("%s-%s", monitoringMetricsUnitID, name),
							"data_stream": map[string]interface{}{
								"type":      "metrics",
								"dataset":   fmt.Sprintf("elastic_agent.%s", name),
								"namespace": monitoringNamespace,
							},
							"metricsets":              []interface{}{"process"},
							"period":                  metricsCollectionIntervalString,
							"index":                   fmt.Sprintf("metrics-elastic_agent.%s-%s", name, monitoringNamespace),
							"process.pid":             comp,
							"process.cgroups.enabled": false,
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
									"add_fields": map[string]interface{}{
										"target": "component",
										"fields": map[string]interface{}{
											"binary": name,
											"id":     compState.ID,
										},
									},
								},
							},
						},
					},
				})
			}

		}
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

func prefixedEndpoint(endpoint string) string {
	if endpoint == "" || strings.HasPrefix(endpoint, httpPlusPrefix) || strings.HasPrefix(endpoint, httpPrefix) {
		return endpoint
	}

	return httpPlusPrefix + endpoint
}

func monitoringFile(id string) string {
	endpoint := utils.SocketURLWithFallback(id, paths.TempDir())
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

		// I should be able to see the filebeat input metrics
		map[string]interface{}{
			"from": "http.filebeat_input",
			"to":   "filebeat_input",
		},
	}

	return fromToMap
}

func isSupportedMetricsBinary(binaryName string) bool {
	for _, supportedBinary := range supportedMetricsComponents {
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
