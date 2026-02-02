// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package component

import (
	"crypto/sha256"
	_ "embed"
	"fmt"
	"maps"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"unicode"

	koanfmaps "github.com/knadh/koanf/maps"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/monitoring/monitoringhelpers"

	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/elastic-agent/internal/pkg/otel/translate"

	"github.com/elastic/elastic-agent/pkg/component"
	"github.com/elastic/elastic-agent/pkg/utils"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/internal/pkg/config"
	monitoringCfg "github.com/elastic/elastic-agent/internal/pkg/core/monitoring/config"
	otelMonitoring "github.com/elastic/elastic-agent/internal/pkg/otel/monitoring"
)

const (
	// args: data path, pipeline name, application name
	logFileFormat = "%s/logs/%s"
	// args: data path, install path, pipeline name, application name
	logFileFormatWin = "%s\\logs\\%s"

	// args: pipeline name, application name
	agentMbEndpointFileFormatWin = `npipe:///elastic-agent`

	httpPlusPrefix   = "http+"
	httpPrefix       = "http"
	fileSchemePrefix = "file"
	unixSchemePrefix = "unix"

	outputsKey                 = "outputs"
	inputsKey                  = "inputs"
	idKey                      = "id"
	agentKey                   = "agent"
	useOutputKey               = "use_output"
	failureThresholdKey        = "failure_threshold"
	MonitoringOutput           = "monitoring"
	defaultMonitoringNamespace = "default"
	agentName                  = "elastic-agent"
	metricBeatName             = "metricbeat"
	fileBeatName               = "filebeat"
	collectorName              = "collector"

	monitoringMetricsUnitID = "metrics-monitoring"
	monitoringFilesUnitsID  = "filestream-monitoring"

	windowsOS = "windows"
)

var (
	errNoOutputPresent         = errors.New("outputs not part of the config")
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
	logger          *logp.Logger
}

// componentInfo is the information necessary to generate monitoring configuration for a component. We don't just use
// the Component struct here because we also want to generate configurations for the monitoring components themselves,
// but without generating the full Component for them.
type componentInfo struct {
	ID             string
	BinaryName     string
	InputSpec      *component.InputRuntimeSpec
	Pid            uint64
	RuntimeManager component.RuntimeManager
}

type monitoringConfig struct {
	C *monitoringCfg.MonitoringConfig `config:"agent.monitoring"`
}

// New creates a new BeatsMonitor instance.
func New(
	enabled bool,
	operatingSystem string,
	cfg *monitoringCfg.MonitoringConfig,
	agentInfo info.Agent,
	logger *logp.Logger,
) *BeatsMonitor {
	return &BeatsMonitor{
		enabled: enabled,
		config: &monitoringConfig{
			C: cfg,
		},
		operatingSystem: operatingSystem,
		agentInfo:       agentInfo,
		logger:          logger,
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

	newConfig := monitoringConfig{
		C: monitoringCfg.DefaultConfig(),
	}

	if err := rawConfig.UnpackTo(&newConfig); err != nil {
		return errors.New(err, "failed to unpack monitoring config during reload")
	}

	b.config = &newConfig
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
	componentIDPidMap map[string]uint64,
) (map[string]interface{}, error) {
	if !b.Enabled() {
		return nil, nil
	}

	cfg := make(map[string]interface{})

	if agentCfg, found := policy[agentKey]; found {
		// The agent section is required for feature flags
		cfg[agentKey] = agentCfg
	}

	outputCfg, err := b.injectMonitoringOutput(policy, cfg)
	if err != nil && !errors.Is(err, errNoOutputPresent) {
		return nil, errors.New(err, "failed to inject monitoring output")
	} else if errors.Is(err, errNoOutputPresent) {
		// nothing to inject, no monitoring output
		return nil, nil
	}

	outputOtelSupportedErr := verifyOutputOtelSupported(outputCfg)
	monitoringRuntime := component.RuntimeManager(b.config.C.RuntimeManager)
	if outputOtelSupportedErr != nil {
		b.logger.Warnf("otel runtime is not supported for monitoring output, switching to process runtime, reason: %v", outputOtelSupportedErr)
		monitoringRuntime = monitoringCfg.ProcessRuntimeManager
	}
	outputOtelSupported := outputOtelSupportedErr == nil
	componentInfos := b.getComponentInfos(components, monitoringRuntime, outputOtelSupported, componentIDPidMap)

	// initializes inputs collection so injectors don't have to deal with it
	b.initInputs(cfg)

	if b.config.C.MonitorLogs {
		if err := b.injectLogsInput(cfg, componentInfos, MonitoringOutput, monitoringRuntime); err != nil {
			return nil, errors.New(err, "failed to inject monitoring output")
		}
	}

	if b.config.C.MonitorMetrics {
		if err := b.injectMetricsInput(cfg, componentInfos, monitoringRuntime); err != nil {
			return nil, errors.New(err, "failed to inject monitoring output")
		}
	}
	return cfg, nil
}

// EnrichArgs enriches arguments provided to application, in order to enable
// monitoring
func (b *BeatsMonitor) EnrichArgs(unit, binary string, args []string) []string {
	configMap := b.ComponentMonitoringConfig(unit, binary)
	flattenedMap, _ := koanfmaps.Flatten(configMap, nil, ".")

	appendix := make([]string, 0, 20)
	keys := slices.Sorted(maps.Keys(flattenedMap))
	for _, key := range keys {
		value := flattenedMap[key]
		appendix = append(appendix, "-E", fmt.Sprintf("%s=%v", key, value))
	}

	return append(args, appendix...)
}

// ComponentMonitoringConfig returns config for enabling monitoring in the component application.
// To be able to monitor a process implementing a component, we need to tell it if and how it should expose its telemetry.
// Other than enabling features, we set the unix domain socket name on which the application should start its
// monitoring http server.
func (b *BeatsMonitor) ComponentMonitoringConfig(unitID, binary string) map[string]any {
	if !b.enabled {
		// even if monitoring is disabled enrich args.
		// the only way to skip it is by disabling monitoring by feature flag
		return nil
	}

	// only beats understand these flags
	if !isSupportedBeatsBinary(binary) {
		return nil
	}

	configMap := make(map[string]any)
	endpoint := monitoringhelpers.BeatsMonitoringEndpoint(unitID)
	if endpoint != "" {
		httpConfigMap := map[string]any{
			"enabled": true,
			"host":    endpoint,
		}
		if b.config.C.Pprof != nil && b.config.C.Pprof.Enabled {
			httpConfigMap["pprof"] = map[string]any{
				"enabled": true,
			}
		}
		if b.config.C.HTTP != nil && b.config.C.HTTP.Buffer != nil && b.config.C.HTTP.Buffer.Enabled {
			httpConfigMap["buffer"] = map[string]any{
				"enabled": true,
			}
		}
		configMap["http"] = httpConfigMap
	}

	if !b.config.C.LogMetrics {
		configMap["logging"] = map[string]any{
			"metrics": map[string]any{
				"enabled": false,
			},
		}
	}

	return configMap
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

// Returns true if any component in the list uses the otel runtime.
func usingOtelRuntime(componentInfos []componentInfo) bool {
	for _, ci := range componentInfos {
		if ci.RuntimeManager == component.OtelRuntimeManager {
			return true
		}
	}
	return false
}

// Cleanup removes files that were created for monitoring.
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

// injectMonitoringOutput injects the monitoring output into the configuration. It takes an existing output named
// `monitoringOutputName` and makes a copy of it named `monitoring`. It returns the output configuration.
func (b *BeatsMonitor) injectMonitoringOutput(source, dest map[string]interface{}) (map[string]any, error) {
	monitoringOutputName := b.config.C.UseOutput
	outputsNode, found := source[outputsKey]
	if !found {
		return nil, errNoOutputPresent
	}

	outputs, ok := outputsNode.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("outputs not a map")
	}

	outputNode, found := outputs[monitoringOutputName]
	if !found {
		return nil, fmt.Errorf("output %q used for monitoring not found", monitoringOutputName)
	}

	outputMap, ok := outputNode.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("output %q used for monitoring not a map", monitoringOutputName)
	}

	monitoringOutputs := map[string]interface{}{
		MonitoringOutput: outputNode,
	}

	dest[outputsKey] = monitoringOutputs

	return outputMap, nil
}

// getComponentInfos returns a slice of componentInfo structs based on the provided components. This slice contains
// all the information needed to generate the monitoring configuration for these components, as well as configuration
// for new components which are going to be doing the monitoring.
func (b *BeatsMonitor) getComponentInfos(
	components []component.Component,
	monitoringRuntime component.RuntimeManager,
	outputOtelSupported bool,
	componentIDPidMap map[string]uint64,
) []componentInfo {
	componentInfos := make([]componentInfo, 0, len(components))
	for _, comp := range components {
		compInfo := componentInfo{
			ID:             comp.ID,
			BinaryName:     comp.BinaryName(),
			InputSpec:      comp.InputSpec,
			RuntimeManager: comp.RuntimeManager,
		}
		if pid, ok := componentIDPidMap[comp.ID]; ok {
			compInfo.Pid = pid
		}
		componentInfos = append(componentInfos, compInfo)
	}
	if b.config.C.MonitorMetrics {
		componentInfos = append(componentInfos,
			componentInfo{
				ID:             fmt.Sprintf("beat/%s", monitoringMetricsUnitID),
				BinaryName:     metricBeatName,
				RuntimeManager: monitoringRuntime,
			},
			componentInfo{
				ID:             fmt.Sprintf("http/%s", monitoringMetricsUnitID),
				BinaryName:     metricBeatName,
				RuntimeManager: monitoringRuntime,
			})
	}
	if b.config.C.MonitorLogs {
		componentInfos = append(componentInfos, componentInfo{
			ID:             monitoringFilesUnitsID,
			BinaryName:     fileBeatName,
			RuntimeManager: monitoringRuntime,
		})
	}
	// sort the components to ensure a consistent order of inputs in the configuration
	slices.SortFunc(componentInfos, func(a, b componentInfo) int {
		return strings.Compare(a.ID, b.ID)
	})
	return componentInfos
}

// injectLogsInput adds logging configs for component monitoring to the `cfg` map
func (b *BeatsMonitor) injectLogsInput(
	cfg map[string]interface{},
	componentInfos []componentInfo,
	monitoringOutput string,
	monitoringRuntime component.RuntimeManager,
) error {
	logsDrop := filepath.Dir(loggingPath("unit", b.operatingSystem))

	streams := []any{b.getAgentFilestreamStream(logsDrop)}

	streams = append(streams, b.getServiceComponentFilestreamStreams(componentInfos)...)

	input := map[string]interface{}{
		idKey:                   fmt.Sprintf("%s-agent", monitoringFilesUnitsID),
		"name":                  fmt.Sprintf("%s-agent", monitoringFilesUnitsID),
		"type":                  "filestream",
		useOutputKey:            monitoringOutput,
		"streams":               streams,
		"_runtime_experimental": string(monitoringRuntime),
	}

	inputs := []any{input}
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
	componentInfos []componentInfo,
	monitoringRuntime component.RuntimeManager,
) error {
	monitoringNamespace := b.monitoringNamespace()

	beatsStreams := b.getBeatsStreams(componentInfos)
	httpStreams := b.getHttpStreams(componentInfos)

	inputs := []interface{}{
		map[string]interface{}{
			idKey:        fmt.Sprintf("%s-beats", monitoringMetricsUnitID),
			"name":       fmt.Sprintf("%s-beats", monitoringMetricsUnitID),
			"type":       "beat/metrics",
			useOutputKey: MonitoringOutput,
			"data_stream": map[string]interface{}{
				"namespace": monitoringNamespace,
			},
			"streams":               beatsStreams,
			"_runtime_experimental": string(monitoringRuntime),
		},
		map[string]interface{}{
			idKey:        fmt.Sprintf("%s-agent", monitoringMetricsUnitID),
			"name":       fmt.Sprintf("%s-agent", monitoringMetricsUnitID),
			"type":       "http/metrics",
			useOutputKey: MonitoringOutput,
			"data_stream": map[string]interface{}{
				"namespace": monitoringNamespace,
			},
			"streams":               httpStreams,
			"_runtime_experimental": string(monitoringRuntime),
		},
	}

	// add system/process metrics for services that can't be monitored via json/beats metrics
	inputs = append(inputs, b.getServiceComponentProcessMetricInputs(
		componentInfos)...)

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

// getAgentFilestreamStream returns the filestream stream definition for collecting agent logs.
func (b *BeatsMonitor) getAgentFilestreamStream(logsDrop string) any {
	monitoringNamespace := b.monitoringNamespace()
	return map[string]any{
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
		"processors": processorsForAgentFilestream(),
	}
}

// getServiceComponentFilestreamStreams returns filestream stream definitions for collecting logs of components running as
// services.
func (b *BeatsMonitor) getServiceComponentFilestreamStreams(componentInfos []componentInfo) []any {
	streams := []any{}
	monitoringNamespace := b.monitoringNamespace()
	// service components that define a log path are monitored using its own stream in the monitor
	for _, compInfo := range componentInfos {
		if compInfo.InputSpec == nil || compInfo.InputSpec.Spec.Service == nil || compInfo.InputSpec.Spec.Service.Log == nil || compInfo.InputSpec.Spec.Service.Log.Path == "" {
			// only monitor service inputs that define a log path
			continue
		}
		sanitizedBinaryName := sanitizeName(compInfo.BinaryName) // conform with index naming policy
		dataset := fmt.Sprintf("elastic_agent.%s", sanitizedBinaryName)
		streams = append(streams, map[string]interface{}{
			idKey:  fmt.Sprintf("%s-%s", monitoringFilesUnitsID, compInfo.ID),
			"type": "filestream",
			"paths": []interface{}{
				compInfo.InputSpec.Spec.Service.Log.Path,
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
			"processors": processorsForServiceComponentFilestream(compInfo, dataset),
		})
	}
	return streams
}

// getHttpStreams returns stream definitions for http/metrics inputs.
// Note: The return type must be []any due to protobuf serialization quirks.
func (b *BeatsMonitor) getHttpStreams(
	componentInfos []componentInfo,
) []any {
	monitoringNamespace := b.monitoringNamespace()
	sanitizedAgentName := sanitizeName(agentName)
	indexName := fmt.Sprintf("metrics-elastic_agent.%s-%s", sanitizedAgentName, monitoringNamespace)
	dataset := fmt.Sprintf("elastic_agent.%s", sanitizedAgentName)
	metricsCollectionIntervalString := b.config.C.MetricsPeriod.String()
	failureThreshold := b.config.C.FailureThreshold
	httpStreams := make([]any, 0, len(componentInfos))

	agentStream := map[string]any{
		idKey: fmt.Sprintf("%s-agent", monitoringMetricsUnitID),
		"data_stream": map[string]interface{}{
			"type":      "metrics",
			"dataset":   dataset,
			"namespace": monitoringNamespace,
		},
		"metricsets": []interface{}{"json"},
		"path":       "/stats",
		"hosts":      []interface{}{HttpPlusAgentMonitoringEndpoint(b.config.C)},
		"namespace":  "agent",
		"period":     metricsCollectionIntervalString,
		"index":      indexName,
		"processors": processorsForAgentHttpStream(agentName, agentName, agentName, monitoringNamespace, dataset, b.agentInfo),
	}
	if failureThreshold != nil {
		agentStream[failureThresholdKey] = *failureThreshold
	}
	httpStreams = append(httpStreams, agentStream)

	if usingOtelRuntime(componentInfos) {
		edotSubprocessStream := map[string]any{
			idKey: fmt.Sprintf("%s-edot-collector", monitoringMetricsUnitID),
			"data_stream": map[string]interface{}{
				"type":      "metrics",
				"dataset":   dataset,
				"namespace": monitoringNamespace,
			},
			"metricsets": []interface{}{"json"},
			"path":       "/stats",
			"hosts":      []interface{}{PrefixedEndpoint(otelMonitoring.EDOTMonitoringEndpoint())},
			"namespace":  "agent",
			"period":     metricsCollectionIntervalString,
			"index":      indexName,
			"processors": processorsForAgentHttpStream(agentName, otelMonitoring.EDOTComponentID, otelMonitoring.EDOTComponentID, monitoringNamespace, dataset, b.agentInfo),
		}
		if failureThreshold != nil {
			edotSubprocessStream[failureThresholdKey] = *failureThreshold
		}
		httpStreams = append(httpStreams, edotSubprocessStream)
	}

	for _, compInfo := range componentInfos {
		binaryName := compInfo.BinaryName
		if !isSupportedMetricsBinary(binaryName) {
			continue
		}

		endpoints := []interface{}{PrefixedEndpoint(monitoringhelpers.BeatsMonitoringEndpoint(compInfo.ID))}
		name := sanitizeName(binaryName)

		// Do not create http streams if runtime-manager is otel and binary is of beat type
		if compInfo.RuntimeManager != component.OtelRuntimeManager || !strings.HasSuffix(binaryName, "beat") {
			httpStream := map[string]interface{}{
				idKey: fmt.Sprintf("%s-%s-1", monitoringMetricsUnitID, name),
				"data_stream": map[string]interface{}{
					"type":      "metrics",
					"dataset":   dataset,
					"namespace": monitoringNamespace,
				},
				"metricsets": []interface{}{"json"},
				"hosts":      endpoints,
				"path":       "/stats",
				"namespace":  "agent",
				"period":     metricsCollectionIntervalString,
				"index":      indexName,
				"processors": processorsForHttpStream(binaryName, compInfo.ID, dataset, b.agentInfo, compInfo.RuntimeManager),
			}
			if failureThreshold != nil {
				httpStream[failureThresholdKey] = *failureThreshold
			}
			httpStreams = append(httpStreams, httpStream)
		}
		// specifically for filebeat, we include input metrics
		if strings.EqualFold(name, "filebeat") {
			fbDataStreamName := "filebeat_input"
			fbDataset := fmt.Sprintf("elastic_agent.%s", fbDataStreamName)
			fbIndexName := fmt.Sprintf("metrics-elastic_agent.%s-%s", fbDataStreamName, monitoringNamespace)
			fbStream := map[string]any{
				idKey: fmt.Sprintf("%s-%s-1", monitoringMetricsUnitID, name),
				"data_stream": map[string]interface{}{
					"type":      "metrics",
					"dataset":   fbDataset,
					"namespace": monitoringNamespace,
				},
				"metricsets":    []interface{}{"json"},
				"hosts":         endpoints,
				"path":          "/inputs/",
				"namespace":     fbDataStreamName,
				"json.is_array": true,
				"period":        metricsCollectionIntervalString,
				"index":         fbIndexName,
				"processors":    processorsForHttpStream(binaryName, compInfo.ID, fbDataset, b.agentInfo, compInfo.RuntimeManager),
			}
			if failureThreshold != nil {
				fbStream[failureThresholdKey] = *failureThreshold
			}
			httpStreams = append(httpStreams, fbStream)
		}
	}

	return httpStreams
}

// getBeatsStreams returns stream definitions for beats inputs.
// Note: The return type must be []any due to protobuf serialization quirks.
func (b *BeatsMonitor) getBeatsStreams(
	componentInfos []componentInfo,
) []any {
	monitoringNamespace := b.monitoringNamespace()
	beatsStreams := make([]any, 0, len(componentInfos))

	for _, compInfo := range componentInfos {
		binaryName := compInfo.BinaryName
		if !isSupportedBeatsBinary(binaryName) {
			continue
		}

		endpoints := []interface{}{PrefixedEndpoint(utils.SocketURLWithFallback(compInfo.ID, paths.TempDir()))}
		name := sanitizeName(binaryName)
		dataset := fmt.Sprintf("elastic_agent.%s", name)
		indexName := fmt.Sprintf("metrics-elastic_agent.%s-%s", name, monitoringNamespace)

		beatsStream := map[string]interface{}{
			idKey: fmt.Sprintf("%s-", monitoringMetricsUnitID) + name,
			"data_stream": map[string]interface{}{
				"type":      "metrics",
				"dataset":   dataset,
				"namespace": monitoringNamespace,
			},
			"metricsets": []interface{}{"stats"},
			"hosts":      endpoints,
			"period":     b.config.C.MetricsPeriod.String(),
			"index":      indexName,
			"processors": processorsForBeatsStream(binaryName, compInfo.ID, monitoringNamespace, dataset, b.agentInfo, compInfo.RuntimeManager),
		}

		if b.config.C.FailureThreshold != nil {
			beatsStream[failureThresholdKey] = *b.config.C.FailureThreshold
		}

		beatsStreams = append(beatsStreams, beatsStream)
	}

	return beatsStreams
}

// getServiceComponentProcessMetricInputs returns input definitions for collecting process metrics of components
// running as services.
// Note: The return type must be []any due to protobuf serialization quirks.
func (b *BeatsMonitor) getServiceComponentProcessMetricInputs(
	componentInfos []componentInfo,
) []any {
	monitoringNamespace := b.monitoringNamespace()
	inputs := []any{}
	for _, compInfo := range componentInfos {
		if compInfo.InputSpec == nil || compInfo.InputSpec.Spec.Service == nil || compInfo.Pid == 0 {
			continue
		}
		// If there's a checkin PID and the corresponding component has a service spec section, add a system/process config
		name := sanitizeName(compInfo.BinaryName)
		dataset := fmt.Sprintf("elastic_agent.%s", name)
		input := map[string]interface{}{
			idKey:        fmt.Sprintf("%s-%s", monitoringMetricsUnitID, name),
			"name":       fmt.Sprintf("%s-%s", monitoringMetricsUnitID, name),
			"type":       "system/metrics",
			useOutputKey: MonitoringOutput,
			"data_stream": map[string]interface{}{
				"namespace": monitoringNamespace,
			},
			"streams": []interface{}{
				map[string]interface{}{
					idKey: fmt.Sprintf("%s-%s", monitoringMetricsUnitID, name),
					"data_stream": map[string]interface{}{
						"type":      "metrics",
						"dataset":   dataset,
						"namespace": monitoringNamespace,
					},
					"metricsets":              []interface{}{"process"},
					"period":                  b.config.C.MetricsPeriod.String(),
					"index":                   fmt.Sprintf("metrics-elastic_agent.%s-%s", name, monitoringNamespace),
					"process.pid":             compInfo.Pid,
					"process.cgroups.enabled": false,
					"processors":              processorsForProcessMetrics(name, compInfo.ID, monitoringNamespace, dataset, b.agentInfo),
				},
			},
		}
		inputs = append(inputs, input)
	}
	return inputs
}

// processorsForAgentFilestream returns processors used for agent logs in a filestream input.
func processorsForAgentFilestream() []any {
	processors := []any{
		// drop all events from monitoring components (do it early)
		// without dropping these events the filestream gets stuck in an infinite loop
		// if filestream hits an issue publishing the events it logs an error which then filestream monitor
		// will read from the logs and try to also publish that new log message (thus the infinite loop).
		dropEventsFromMonitoringComponentsProcessor(),
		// drop periodic metrics logs (those are useful mostly in diagnostic dumps where we collect log files)
		dropPeriodicMetricsLogsProcessor(),
		// drop event logs
		dropEventLogs(),
		// drop potential sensitive fields emitted by elasticsearch exporter logs
		dropSensitiveFieldsFromElasticSearchExporterLogs(),
	}
	// if the event is from a component, use the component's dataset
	processors = append(processors, useComponentDatasetProcessors()...)
	processors = append(processors,
		// coming from logger, added by agent (drop)
		dropEcsVersionFieldProcessor(),
		// adjust destination data_stream based on the data_stream fields
		addFormattedIndexProcessor(),
	)
	return processors
}

// processorsForServiceComponentFilestream returns processors used for filestream streams for components running as
// Services.
func processorsForServiceComponentFilestream(compInfo componentInfo, dataset string) []any {
	return []interface{}{
		map[string]interface{}{
			// component information must be injected because it's not a subprocess
			"add_fields": map[string]interface{}{
				"target": "component",
				"fields": map[string]interface{}{
					"id":      compInfo.ID,
					"type":    compInfo.InputSpec.InputType,
					"binary":  compInfo.BinaryName,
					"dataset": dataset,
				},
			},
		},
		map[string]interface{}{
			// injecting component log source to stay aligned with command runtime logs
			"add_fields": map[string]interface{}{
				"target": "log",
				"fields": map[string]interface{}{
					"source": compInfo.ID,
				},
			},
		},
	}
}

// processorsForProcessMetrics returns processors used for process metrics.
func processorsForProcessMetrics(binaryName, unitID, namespace, dataset string, agentInfo info.Agent) []any {
	return []any{
		addDataStreamFieldsProcessor(dataset, namespace),
		addEventFieldsProcessor(dataset),
		addElasticAgentFieldsProcessor(binaryName, agentInfo),
		addAgentFieldsProcessor(agentInfo.AgentID()),
		addComponentFieldsProcessor(binaryName, unitID),
	}
}

// processorsForBeatsStream returns the processors used for metric streams in the beats input.
func processorsForBeatsStream(
	binaryName, unitID, namespace, dataset string,
	agentInfo info.Agent,
	runtimeManager component.RuntimeManager,
) []any {
	processors := []any{
		addDataStreamFieldsProcessor(dataset, namespace),
		addEventFieldsProcessor(dataset),
		addElasticAgentFieldsProcessor(binaryName, agentInfo),
		addAgentFieldsProcessor(agentInfo.AgentID()),
		addComponentFieldsProcessor(binaryName, unitID),
	}
	if runtimeManager == component.OtelRuntimeManager { // we don't want process metrics for beats receivers
		fieldsToDrop := []any{
			"beat.stats.cgroup",
			"beat.stats.cpu",
			"beat.stats.handles",
			"beat.stats.memstats",
			"beat.stats.runtime",
		}
		processors = append(processors, map[string]interface{}{
			"drop_fields": map[string]interface{}{
				"fields":         fieldsToDrop,
				"ignore_missing": true,
			},
		})
	}
	return processors
}

// processorsForBeatsStream returns the processors used for metric streams in the beats input.
func processorsForHttpStream(binaryName, unitID, dataset string, agentInfo info.Agent, runtimeManager component.RuntimeManager) []any {
	sanitizedName := sanitizeName(binaryName)
	fieldsToDrop := []any{"http"}
	if runtimeManager == component.OtelRuntimeManager { // we don't want process metrics for beats receivers
		fieldsToDrop = append(fieldsToDrop, "system")
	}
	return []interface{}{
		addEventFieldsProcessor(dataset),
		addElasticAgentFieldsProcessor(sanitizedName, agentInfo),
		addAgentFieldsProcessor(agentInfo.AgentID()),
		addCopyFieldsProcessor(httpCopyRules(), true, false),
		dropFieldsProcessor(fieldsToDrop, true),
		addComponentFieldsProcessor(binaryName, unitID),
	}
}

// processorsForAgentHttpStream returns the processors used for the agent metric stream in the beats input.
func processorsForAgentHttpStream(binaryName, processName, unitID, namespace, dataset string, agentInfo info.Agent) []any {
	return []interface{}{
		addDataStreamFieldsProcessor(dataset, namespace),
		addEventFieldsProcessor(dataset),
		addElasticAgentFieldsProcessor(processName, agentInfo),
		addAgentFieldsProcessor(agentInfo.AgentID()),
		addCopyFieldsProcessor(httpCopyRules(), true, false),
		dropFieldsProcessor([]any{"http"}, true),
		addComponentFieldsProcessor(binaryName, unitID),
	}
}

// addElasticAgentFieldsProcessor returns a processor definition that adds agent information in an `elastic_agent` field.
func addElasticAgentFieldsProcessor(processName string, agentInfo info.Agent) map[string]any {
	return map[string]any{
		"add_fields": map[string]any{
			"target": "elastic_agent",
			"fields": map[string]any{
				"id":       agentInfo.AgentID(),
				"version":  agentInfo.Version(),
				"snapshot": agentInfo.Snapshot(),
				"process":  processName,
			},
		},
	}
}

// addAgentFieldsProcessor returns a processor definition that adds the agent ID under an `agent.id` field.
func addAgentFieldsProcessor(agentID string) map[string]any {
	return map[string]interface{}{
		"add_fields": map[string]interface{}{
			"target": "agent",
			"fields": map[string]interface{}{
				"id": agentID,
			},
		},
	}
}

// addComponentFieldsProcessor returns a processor definition that adds component information.
func addComponentFieldsProcessor(binaryName, unitID string) map[string]any {
	return map[string]interface{}{
		"add_fields": map[string]interface{}{
			"target": "component",
			"fields": map[string]interface{}{
				"id":     unitID,
				"binary": binaryName,
			},
		},
	}
}

// addDataStreamFieldsProcessor returns a processor definition that adds datastream information.
func addDataStreamFieldsProcessor(dataset, namespace string) map[string]any {
	return map[string]interface{}{
		"add_fields": map[string]interface{}{
			"target": "data_stream",
			"fields": map[string]interface{}{
				"type":      "metrics",
				"dataset":   dataset,
				"namespace": namespace,
			},
		},
	}
}

// addEventFieldsProcessor returns a processor definition that adds an `event.dataset` field.
func addEventFieldsProcessor(dataset string) map[string]any {
	return map[string]interface{}{
		"add_fields": map[string]interface{}{
			"target": "event",
			"fields": map[string]interface{}{
				"dataset": dataset,
			},
		},
	}
}

// addCopyRulesProcessor returns a processor that copies fields according to the provided rules.
func addCopyFieldsProcessor(copyRules []any, ignoreMissing bool, failOnError bool) map[string]any {
	return map[string]interface{}{
		"copy_fields": map[string]interface{}{
			"fields":         copyRules,
			"ignore_missing": ignoreMissing,
			"fail_on_error":  failOnError,
		},
	}
}

// dropFieldsProcessor returns a processor which drops the provided fields.
func dropFieldsProcessor(fields []any, ignoreMissing bool) map[string]any {
	return map[string]interface{}{
		"drop_fields": map[string]interface{}{
			"fields":         fields,
			"ignore_missing": ignoreMissing,
		},
	}
}

// dropElasticSearchExporterLogs returns a processor which drops fields from logs emitted by elasticsearch exporter,  that may contain sensitive data.
func dropSensitiveFieldsFromElasticSearchExporterLogs() map[string]any {
	return map[string]interface{}{
		"drop_fields": map[string]interface{}{
			"fields": []any{"error.reason"},
			"when": map[string]interface{}{
				"contains": map[string]interface{}{
					"message": "failed to index document", // this message come from ES exporter
				},
			},
		},
	}
}

// dropEventLogs returns a processor which drops all event that contains log.type:event field
func dropEventLogs() map[string]any {
	return map[string]interface{}{
		"drop_event": map[string]interface{}{
			"when": map[string]interface{}{
				"equals": map[string]interface{}{
					"log.type": "event",
				},
			},
		},
	}
}

// dropEventsFromMonitoringComponentsProcessor returns a processor which drops all events from monitoring components.
// We identify a monitoring component by looking at their ID. They all end in `-monitoring`, e.g:
// - "beat/metrics-monitoring"
// - "filestream-monitoring"
// - "http/metrics-monitoring"
func dropEventsFromMonitoringComponentsProcessor() map[string]any {
	return map[string]interface{}{
		"drop_event": map[string]interface{}{
			"when": map[string]interface{}{
				"regexp": map[string]interface{}{
					"component.id": ".*-monitoring$",
				},
			},
		},
	}
}

// dropPeriodicMetricsLogsProcessor returns a processor which drops logs about periodic metrics. This is done by
// matching on the start of the log message.
func dropPeriodicMetricsLogsProcessor() map[string]any {
	return map[string]interface{}{
		"drop_event": map[string]interface{}{
			"when": map[string]interface{}{
				"regexp": map[string]interface{}{
					"message": "(^Non-zero metrics in the last)|(^Collector internal telemetry metrics updated)",
				},
			},
		},
	}
}

// useComponentDatasetProcessors returns a list of processors which replace data_stream.dataset with component.dataset
// if the latter is set. It also sets event.dataset to the same value. This is used to ensure logs from components
// routed to the elastic-agent logger get sent to the component-specific dataset.
func useComponentDatasetProcessors() []any {
	return []any{
		// copy original dataset so we can drop the dataset field
		map[string]any{
			"copy_fields": map[string]any{
				"fields": []any{
					map[string]any{
						"from": "data_stream.dataset",
						"to":   "data_stream.dataset_original",
					},
				},
			},
		},
		// drop the dataset field so following copy_field can copy to it
		map[string]any{
			"drop_fields": map[string]any{
				"fields": []any{
					"data_stream.dataset",
				},
			},
		},
		// copy component.dataset as the real dataset
		map[string]any{
			"copy_fields": map[string]any{
				"fields": []any{
					map[string]any{
						"from": "component.dataset",
						"to":   "data_stream.dataset",
					},
				},
				"fail_on_error":  false,
				"ignore_missing": true,
			},
		},
		// possible it's a log message from agent itself (doesn't have component.dataset)
		map[string]any{
			"copy_fields": map[string]any{
				"when": map[string]any{
					"not": map[string]any{
						"has_fields": []any{
							"data_stream.dataset",
						},
					},
				},
				"fields": []any{
					map[string]any{
						"from": "data_stream.dataset_original",
						"to":   "data_stream.dataset",
					},
				},
				"fail_on_error": false,
			},
		},
		// drop the original dataset copied and the event.dataset (as it will be updated)
		map[string]any{
			"drop_fields": map[string]any{
				"fields": []any{
					"data_stream.dataset_original",
					"event.dataset",
				},
			},
		},
		// update event.dataset with the now used data_stream.dataset
		map[string]any{
			"copy_fields": map[string]any{
				"fields": []any{
					map[string]any{
						"from": "data_stream.dataset",
						"to":   "event.dataset",
					},
				},
			},
		},
	}
}

// dropEcsVersionFieldProcessor returns a processor which drops the ecs.version field from the event.
func dropEcsVersionFieldProcessor() map[string]any {
	return map[string]any{
		"drop_fields": map[string]any{
			"fields": []any{
				"ecs.version",
			},
			"ignore_missing": true,
		},
	}
}

// addFormattedIndexProcessor returns a processor which sets the destination index for an event based on a format string.
func addFormattedIndexProcessor() map[string]any {
	return map[string]any{
		"add_formatted_index": map[string]any{
			"index": "%{[data_stream.type]}-%{[data_stream.dataset]}-%{[data_stream.namespace]}",
		},
	}
}

// sanitizeName sanitizes the input name to make it a valid part of ES index names.
func sanitizeName(name string) string {
	return strings.ReplaceAll(strings.ReplaceAll(name, "-", "_"), "/", "_")
}

func loggingPath(id, operatingSystem string) string {
	id = strings.ReplaceAll(id, string(filepath.Separator), "-")
	if operatingSystem == windowsOS {
		return fmt.Sprintf(logFileFormatWin, paths.Home(), id)
	}

	return fmt.Sprintf(logFileFormat, paths.Home(), id)
}

func PrefixedEndpoint(endpoint string) string {
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
func HttpPlusAgentMonitoringEndpoint(cfg *monitoringCfg.MonitoringConfig) string {
	return PrefixedEndpoint(AgentMonitoringEndpoint(cfg))
}

// AgentMonitoringEndpoint provides an agent monitoring endpoint path.
func AgentMonitoringEndpoint(cfg *monitoringCfg.MonitoringConfig) string {
	if cfg != nil && cfg.Enabled {
		return "http://" + net.JoinHostPort(cfg.HTTP.Host, strconv.Itoa(cfg.HTTP.Port))
	}

	if runtime.GOOS == windowsOS {
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

		// I should be able to see fd usage. Am I keeping too many files open?
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

func verifyOutputOtelSupported(outputCfg map[string]any) error {
	parsed, err := component.ParseOutput(MonitoringOutput, outputCfg, logp.InfoLevel, nil)
	if err != nil {
		return err
	}

	return translate.VerifyOutputIsOtelSupported(parsed.OutputType, outputCfg)
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
