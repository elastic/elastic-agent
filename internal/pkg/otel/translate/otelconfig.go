// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package translate

import (
	"fmt"
	"path/filepath"
	"slices"
	"strings"

	koanfmaps "github.com/knadh/koanf/maps"

	otelcomponent "go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/confmap"
	"go.opentelemetry.io/collector/pipeline"
	"golang.org/x/exp/maps"

	elasticsearchtranslate "github.com/elastic/beats/v7/libbeat/otelbeat/oteltranslate/outputs/elasticsearch"
	"github.com/elastic/beats/v7/x-pack/filebeat/fbreceiver"
	"github.com/elastic/beats/v7/x-pack/libbeat/management"
	"github.com/elastic/beats/v7/x-pack/metricbeat/mbreceiver"
	"github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/elastic/elastic-agent-libs/config"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/pkg/component"
	"github.com/elastic/elastic-agent/pkg/component/runtime"
)

// This is a prefix we add to all names of Otel entities in the configuration. Its purpose is to avoid collisions with
// user-provided configuration
const OtelNamePrefix = "_agent-component/"

// BeatMonitoringConfigGetter is a function that returns the monitoring configuration for a beat receiver.
type BeatMonitoringConfigGetter func(unitID, binary string) map[string]any
type exporterConfigTranslationFunc func(*config.C) (map[string]any, error)

var (
	OtelSupportedOutputTypes         = []string{"elasticsearch"}
	OtelSupportedInputTypes          = []string{"filestream", "http/metrics", "beat/metrics", "system/metrics"}
	configTranslationFuncForExporter = map[otelcomponent.Type]exporterConfigTranslationFunc{
		otelcomponent.MustNewType("elasticsearch"): translateEsOutputToExporter,
	}
)

// GetOtelConfig returns the Otel collector configuration for the given component model.
// All added component and pipelines names are prefixed with OtelNamePrefix.
// Unsupported components are quietly ignored.
func GetOtelConfig(
	model *component.Model,
	info info.Agent,
	beatMonitoringConfigGetter BeatMonitoringConfigGetter,
) (*confmap.Conf, error) {
	components := getSupportedComponents(model)
	if len(components) == 0 {
		return nil, nil
	}
	otelConfig := confmap.New() // base config, nothing here for now

	for _, comp := range components {
		componentConfig, compErr := getCollectorConfigForComponent(comp, info, beatMonitoringConfigGetter)
		if compErr != nil {
			return nil, compErr
		}
		// the assumption here is that each component will define its own receivers, and the shared exporters
		// will be merged
		mergeErr := otelConfig.Merge(componentConfig)
		if mergeErr != nil {
			return nil, fmt.Errorf("error merging otel config for component %s: %w", comp.ID, mergeErr)
		}
	}
	return otelConfig, nil
}

// IsComponentOtelSupported checks if the given component can be run in an Otel Collector.
func IsComponentOtelSupported(comp *component.Component) bool {
	return slices.Contains(OtelSupportedOutputTypes, comp.OutputType) &&
		slices.Contains(OtelSupportedInputTypes, comp.InputType)
}

// getSupportedComponents returns components from the given model that can be run in an Otel Collector.
func getSupportedComponents(model *component.Model) []*component.Component {
	var supportedComponents []*component.Component

	for _, comp := range model.Components {
		if IsComponentOtelSupported(&comp) {
			supportedComponents = append(supportedComponents, &comp)
		}
	}

	return supportedComponents
}

// getPipelineID returns the pipeline id for the given component.
func getPipelineID(comp *component.Component) (pipeline.ID, error) {
	signal, err := getSignalForComponent(comp)
	if err != nil {
		return pipeline.ID{}, err
	}
	pipelineName := fmt.Sprintf("%s%s", OtelNamePrefix, comp.ID)
	return pipeline.NewIDWithName(signal, pipelineName), nil
}

// getReceiverID returns the receiver id for the given unit and exporter type.
func getReceiverID(receiverType otelcomponent.Type, unitID string) otelcomponent.ID {
	receiverName := fmt.Sprintf("%s%s", OtelNamePrefix, unitID)
	return otelcomponent.NewIDWithName(receiverType, receiverName)
}

// getExporterID returns the exporter id for the given exporter type and output name.
func getExporterID(exporterType otelcomponent.Type, outputName string) otelcomponent.ID {
	exporterName := fmt.Sprintf("%s%s", OtelNamePrefix, outputName)
	return otelcomponent.NewIDWithName(exporterType, exporterName)
}

// getCollectorConfigForComponent returns the Otel collector config required to run the given component.
// This function returns a full, valid configuration that can then be merged with configurations for other components.
func getCollectorConfigForComponent(
	comp *component.Component,
	info info.Agent,
	beatMonitoringConfigGetter BeatMonitoringConfigGetter,
) (*confmap.Conf, error) {

	exportersConfig, outputQueueConfig, err := getExportersConfigForComponent(comp)
	if err != nil {
		return nil, err
	}
	receiversConfig, err := getReceiversConfigForComponent(comp, info, outputQueueConfig, beatMonitoringConfigGetter)

	if err != nil {
		return nil, err
	}
	pipelineID, err := getPipelineID(comp)
	if err != nil {
		return nil, err
	}
	pipelinesConfig := map[string]any{
		pipelineID.String(): map[string][]string{
			"exporters": maps.Keys(exportersConfig),
			"receivers": maps.Keys(receiversConfig),
		},
	}

	fullConfig := map[string]any{
		"receivers": receiversConfig,
		"exporters": exportersConfig,
		"service": map[string]any{
			"pipelines": pipelinesConfig,
		},
	}
	return confmap.NewFromStringMap(fullConfig), nil
}

// getReceiversConfigForComponent returns the receivers configuration for a component. Usually this will be a single
// receiver, but in principle it could be more.
func getReceiversConfigForComponent(
	comp *component.Component,
	info info.Agent,
	outputQueueConfig map[string]any,
	beatMonitoringConfigGetter BeatMonitoringConfigGetter,
) (map[string]any, error) {
	receiverType, err := getReceiverTypeForComponent(comp)
	if err != nil {
		return nil, err
	}
	// this is necessary to convert policy config format to beat config format
	defaultDataStreamType, err := getDefaultDatastreamTypeForComponent(comp)
	if err != nil {
		return nil, err
	}

	// get inputs for all the units
	// we run a single receiver for each component to mirror what beats processes do
	var inputs []map[string]any
	for _, unit := range comp.Units {
		if unit.Type == client.UnitTypeInput {
			unitInputs, err := getInputsForUnit(unit, info, defaultDataStreamType, comp.InputType)
			if err != nil {
				return nil, err
			}
			inputs = append(inputs, unitInputs...)
		}
	}

	receiverId := getReceiverID(receiverType, comp.ID)
	// Beat config inside a beat receiver is nested under an additional key. Not sure if this simple translation is
	// always safe. We should either ensure this is always the case, or have an explicit mapping.
	beatName := strings.TrimSuffix(receiverType.String(), "receiver")
	beatDataPath := filepath.Join(paths.Run(), comp.ID)
	binaryName := getBeatNameForComponent(comp)
	dataset := fmt.Sprintf("elastic_agent.%s", strings.ReplaceAll(strings.ReplaceAll(binaryName, "-", "_"), "/", "_"))

	receiverConfig := map[string]any{
		// the output needs to be otelconsumer
		"output": map[string]any{
			"otelconsumer": map[string]any{},
		},
		// just like we do for beats processes, each receiver needs its own data path
		"path": map[string]any{
			"data": beatDataPath,
		},
		// adds additional context on logs emitted by beatreceivers to uniquely identify per component logs
		"logging": map[string]any{
			"with_fields": map[string]any{
				"component": map[string]interface{}{
					"id":      comp.ID,
					"binary":  binaryName,
					"dataset": dataset,
					"type":    comp.InputType,
				},
				"log": map[string]interface{}{
					"source": comp.ID,
				},
			},
		},
	}
	switch beatName {
	case "filebeat":
		receiverConfig[beatName] = map[string]any{
			"inputs": inputs,
		}
	case "metricbeat":
		receiverConfig[beatName] = map[string]any{
			"modules": inputs,
		}
	}
	// add the output queue config if present
	if outputQueueConfig != nil {
		receiverConfig["queue"] = outputQueueConfig
	}

	// add monitoring config if necessary
	monitoringConfig := beatMonitoringConfigGetter(comp.ID, beatName)
	koanfmaps.Merge(monitoringConfig, receiverConfig)

	return map[string]any{
		receiverId.String(): receiverConfig,
	}, nil
}

// getReceiversConfigForComponent returns the exporters configuration and queue settings for a component. Usually this will be a single
// exporter, but in principle it could be more.
func getExportersConfigForComponent(comp *component.Component) (exporterCfg map[string]any, queueCfg map[string]any, err error) {
	exportersConfig := map[string]any{}
	exporterType, err := getExporterTypeForComponent(comp)
	if err != nil {
		return nil, nil, err
	}
	var queueSettings map[string]any
	for _, unit := range comp.Units {
		if unit.Type == client.UnitTypeOutput {
			var unitExportersConfig map[string]any
			unitExportersConfig, queueSettings, err = unitToExporterConfig(unit, exporterType, comp.InputType)
			if err != nil {
				return nil, nil, err
			}
			for k, v := range unitExportersConfig {
				exportersConfig[k] = v
			}
		}
	}
	return exportersConfig, queueSettings, nil
}

// getBeatNameForComponent returns the beat binary name that would be used to run this component.
func getBeatNameForComponent(comp *component.Component) string {
	// TODO: Add this information directly to the spec?
	if comp.InputSpec == nil || comp.InputSpec.BinaryName != "agentbeat" {
		return ""
	}
	return comp.InputSpec.Spec.Command.Args[0]
}

// getSignalForComponent returns the otel signal for the given component. Currently, this is always logs, even for
// metricbeat.
func getSignalForComponent(comp *component.Component) (pipeline.Signal, error) {
	beatName := getBeatNameForComponent(comp)
	switch beatName {
	case "filebeat", "metricbeat":
		return pipeline.SignalLogs, nil
	default:
		return pipeline.Signal{}, fmt.Errorf("unknown otel signal for input type: %s", comp.InputType)
	}
}

// getReceiverTypeForComponent returns the receiver type for the given component.
func getReceiverTypeForComponent(comp *component.Component) (otelcomponent.Type, error) {
	beatName := getBeatNameForComponent(comp)
	switch beatName {
	case "filebeat":
		return otelcomponent.MustNewType(fbreceiver.Name), nil
	case "metricbeat":
		return otelcomponent.MustNewType(mbreceiver.Name), nil
	default:
		return otelcomponent.Type{}, fmt.Errorf("unknown otel receiver type for input type: %s", comp.InputType)
	}
}

// getExporterTypeForComponent returns the exporter type for the given component.
func getExporterTypeForComponent(comp *component.Component) (otelcomponent.Type, error) {
	switch comp.OutputType {
	case "elasticsearch":
		return otelcomponent.MustNewType("elasticsearch"), nil
	default:
		return otelcomponent.Type{}, fmt.Errorf("unknown otel exporter type for output type: %s", comp.OutputType)
	}
}

// unitToExporterConfig translates a component.Unit to return an otel exporter configuration and output queue settings
func unitToExporterConfig(unit component.Unit, exporterType otelcomponent.Type, inputType string) (exportersCfg map[string]any, queueSettings map[string]any, err error) {
	if unit.Type == client.UnitTypeInput {
		return nil, nil, fmt.Errorf("unit type is an input, expected output: %v", unit)
	}
	configTranslationFunc, ok := configTranslationFuncForExporter[exporterType]
	if !ok {
		return nil, nil, fmt.Errorf("no config translation function for exporter type: %s", exporterType)
	}
	// we'd like to use the same exporter for all outputs with the same name, so we parse out the name for the unit id
	// these will be deduplicated by the configuration merging process at the end
	outputName := strings.TrimPrefix(unit.ID, inputType+"-") // TODO: Use a more structured approach here
	exporterId := getExporterID(exporterType, outputName)

	// translate the configuration
	unitConfigMap := unit.Config.GetSource().AsMap() // this is what beats do in libbeat/management/generate.go
	outputCfgC, err := config.NewConfigFrom(unitConfigMap)
	if err != nil {
		return nil, nil, fmt.Errorf("error translating config for output: %s, unit: %s, error: %w", outputName, unit.ID, err)
	}
	// Config translation function can mutate queue settings defined under output config
	exporterConfig, err := configTranslationFunc(outputCfgC)
	if err != nil {
		return nil, nil, fmt.Errorf("error translating config for output: %s, unit: %s, error: %w", outputName, unit.ID, err)
	}

	exportersCfg = map[string]any{
		exporterId.String(): exporterConfig,
	}

	// If output config contains queue settings defined by user/preset field, it should be promoted to the receiver section
	if ok := outputCfgC.HasField("queue"); ok {
		err := outputCfgC.Unpack(&queueSettings)
		if err != nil {
			return nil, nil, fmt.Errorf("error unpacking queue settings for output: %s, unit: %s, error: %w", outputName, unit.ID, err)
		}
		if queue, ok := queueSettings["queue"].(map[string]any); ok {
			queueSettings = queue
		}
	}

	return exportersCfg, queueSettings, nil
}

// getInputsForUnit returns the beat inputs for a unit. These can directly be plugged into a beats receiver config.
// It mainly calls a conversion function from the control protocol client.
func getInputsForUnit(unit component.Unit, info info.Agent, defaultDataStreamType string, inputType string) ([]map[string]any, error) {
	agentInfo := &client.AgentInfo{
		ID:           info.AgentID(),
		Version:      info.Version(),
		Snapshot:     info.Snapshot(),
		ManagedMode:  runtime.ProtoAgentMode(info),
		Unprivileged: info.Unprivileged(),
	}
	inputs, err := management.CreateInputsFromStreams(unit.Config, defaultDataStreamType, agentInfo)
	if err != nil {
		return nil, err
	}
	// Add the type to each input. CreateInputsFromStreams doesn't do this, each beat does it on its own in a transform
	// function. For filebeat, see: https://github.com/elastic/beats/blob/main/x-pack/filebeat/cmd/agent.go

	for _, input := range inputs {
		// If inputType contains /metrics, use modules to create inputs
		if strings.Contains(inputType, "/metrics") {
			input["module"] = strings.TrimSuffix(inputType, "/metrics")
		} else if _, ok := input["type"]; !ok {
			input["type"] = inputType
		}
	}

	return inputs, nil
}

// getDefaultDatastreamTypeForComponent returns the default datastream type for a given component.
// This is needed to translate from the agent policy config format to the beats config format.
func getDefaultDatastreamTypeForComponent(comp *component.Component) (string, error) {
	beatName := getBeatNameForComponent(comp)
	switch beatName {
	case "filebeat":
		return "logs", nil
	case "metricbeat":
		return "metrics", nil
	default:
		return "", fmt.Errorf("input type not supported by Otel: %s", comp.InputType)
	}
}

// translateEsOutputToExporter translates an elasticsearch output configuration to an elasticsearch exporter configuration.
func translateEsOutputToExporter(cfg *config.C) (map[string]any, error) {
	esConfig, err := elasticsearchtranslate.ToOTelConfig(cfg)
	if err != nil {
		return nil, err
	}
	// we want to use dynamic indexing
	esConfig["logs_index"] = "" // needs to be empty for logs_dynamic_index
	esConfig["logs_dynamic_index"] = map[string]any{"enabled": true}

	// we also want to use dynamic log ids
	esConfig["logs_dynamic_id"] = map[string]any{"enabled": true}

	// for compatibility with beats, we want bodymap mapping
	esConfig["mapping"] = map[string]any{"mode": "bodymap"}
	return esConfig, nil
}
