// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package translate

import (
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"

	"github.com/go-viper/mapstructure/v2"
	koanfmaps "github.com/knadh/koanf/maps"

	"github.com/elastic/elastic-agent-libs/logp"
	componentmonitoring "github.com/elastic/elastic-agent/internal/pkg/agent/application/monitoring/component"

	otelcomponent "go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/confmap"
	"go.opentelemetry.io/collector/pipeline"
	"golang.org/x/exp/maps"

	"github.com/elastic/beats/v7/libbeat/outputs/elasticsearch"
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
type (
	BeatMonitoringConfigGetter    func(unitID, binary string) map[string]any
	exporterConfigTranslationFunc func(*config.C, *logp.Logger) (map[string]any, error)
)

var (
	OtelSupportedOutputTypes        = []string{"elasticsearch"}
	OtelSupportedFilebeatInputTypes = []string{
		"filestream",
		"journald",
		"log",
		"winlog",
	}
	OtelSupportedMetricbeatInputTypes = []string{
		"beat/metrics",
		"http/metrics",
		"kubernetes/metrics",
		"linux/metrics",
		"prometheus/metrics",
		"system/metrics",
	}
	OtelSupportedInputTypes          = slices.Concat(OtelSupportedFilebeatInputTypes, OtelSupportedMetricbeatInputTypes)
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
	logger *logp.Logger,
) (*confmap.Conf, error) {
	components := getSupportedComponents(logger, model)
	if len(components) == 0 {
		return nil, nil
	}
	otelConfig := confmap.New()     // base config, nothing here for now
	extensions := map[string]bool{} // we have to manually handle extensions because otel does not merge lists, it overrides them. This is a known issue: see https://github.com/open-telemetry/opentelemetry-collector/issues/8754

	for _, comp := range components {
		componentConfig, compErr := getCollectorConfigForComponent(comp, info, beatMonitoringConfigGetter, logger)
		if compErr != nil {
			return nil, compErr
		}

		// save the extensions, we deduplicate and add this list at the end
		if componentConfig.IsSet("service::extensions") {
			for _, extension := range componentConfig.Get("service::extensions").([]any) {
				extensionName := extension.(string)
				extensions[extensionName] = true
			}
		}

		// the assumption here is that each component will define its own receivers, and the shared exporters
		// will be merged
		mergeErr := otelConfig.Merge(componentConfig)
		if mergeErr != nil {
			return nil, fmt.Errorf("error merging otel config for component %s: %w", comp.ID, mergeErr)
		}
	}
	// create a deduplicated extensions lists in a deterministic order
	extensionsSlice := maps.Keys(extensions)
	slices.Sort(extensionsSlice)
	// for consistency, we set this back as a slice of any
	untypedExtensions := make([]any, len(extensionsSlice))
	for i, ext := range extensionsSlice {
		untypedExtensions[i] = ext
	}
	extensionsConf := confmap.NewFromStringMap(map[string]any{"service::extensions": untypedExtensions})
	err := otelConfig.Merge(extensionsConf)
	if err != nil {
		return nil, fmt.Errorf("error merging otel extensions: %w", err)
	}
	return otelConfig, nil
}

// VerifyComponentIsOtelSupported verifies that the given component can be run in an Otel Collector. It returns an error
// indicating what the problem is, if it can't.
func VerifyComponentIsOtelSupported(comp *component.Component) error {
	if !slices.Contains(OtelSupportedOutputTypes, comp.OutputType) {
		return fmt.Errorf("unsupported output type: %s", comp.OutputType)
	}

	if !slices.Contains(OtelSupportedInputTypes, comp.InputType) {
		return fmt.Errorf("unsupported input type: %s", comp.InputType)
	}

	// check if the actual configuration is supported. We need to actually generate the config and look for
	// the right kind of error
	_, compErr := getCollectorConfigForComponent(comp, &info.AgentInfo{}, func(unitID, binary string) map[string]any {
		return nil
	}, logp.NewNopLogger())
	if errors.Is(compErr, errors.ErrUnsupported) {
		return fmt.Errorf("unsupported configuration for %s: %w", comp.ID, compErr)
	}

	return nil
}

// getSupportedComponents returns components from the given model that can be run in an Otel Collector.
func getSupportedComponents(logger *logp.Logger, model *component.Model) []*component.Component {
	var supportedComponents []*component.Component

	for _, comp := range model.Components {
		if err := VerifyComponentIsOtelSupported(&comp); err == nil {
			supportedComponents = append(supportedComponents, &comp)
		} else {
			logger.Errorf("unsupported component %s submitted to otel manager, skipping: %v", comp.ID, err)
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

// getBeatsAuthExtensionID returns the id for beatsauth extension
// outputName here is name of the output defined in elastic-agent.yml. For ex: default, monitoring
func getBeatsAuthExtensionID(outputName string) otelcomponent.ID {
	extensionName := fmt.Sprintf("%s%s", OtelNamePrefix, outputName)
	return otelcomponent.NewIDWithName(otelcomponent.MustNewType("beatsauth"), extensionName)
}

// getCollectorConfigForComponent returns the Otel collector config required to run the given component.
// This function returns a full, valid configuration that can then be merged with configurations for other components.
// Note: Lists are not merged and should be handled by the caller of the method
func getCollectorConfigForComponent(
	comp *component.Component,
	info info.Agent,
	beatMonitoringConfigGetter BeatMonitoringConfigGetter,
	logger *logp.Logger,
) (*confmap.Conf, error) {
	exportersConfig, outputQueueConfig, extensionConfig, err := getExportersConfigForComponent(comp, logger)
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

	// we need to convert []string to []interface for this to work
	extensionKey := make([]any, len(maps.Keys(extensionConfig)))
	for i, v := range maps.Keys(extensionConfig) {
		extensionKey[i] = v
	}

	fullConfig := map[string]any{
		"receivers":  receiversConfig,
		"exporters":  exportersConfig,
		"extensions": extensionConfig,
		"service": map[string]any{
			"extensions": extensionKey,
			"pipelines":  pipelinesConfig,
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
	binaryName := GetBeatNameForComponent(comp)
	dataset := fmt.Sprintf("elastic_agent.%s", strings.ReplaceAll(strings.ReplaceAll(binaryName, "-", "_"), "/", "_"))

	receiverConfig := map[string]any{
		// the output needs to be otelconsumer
		"output": map[string]any{
			"otelconsumer": map[string]any{},
		},
		// just like we do for beats processes, each receiver needs its own data path
		"path": map[string]any{
			"data": BeatDataPath(comp.ID),
		},
		// adds additional context on logs emitted by beatreceivers to uniquely identify per component logs
		"logging": map[string]any{
			"with_fields": map[string]any{
				"component": map[string]any{
					"id":      comp.ID,
					"binary":  binaryName,
					"dataset": dataset,
					"type":    comp.InputType,
				},
				"log": map[string]any{
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
	// we enable the basic monitoring endpoint by default, because we want to use it for diagnostics even if
	// agent self-monitoring is disabled
	monitoringConfig := beatMonitoringConfigGetter(comp.ID, beatName)
	if monitoringConfig == nil {
		endpoint := componentmonitoring.BeatsMonitoringEndpoint(comp.ID)
		monitoringConfig = map[string]any{
			"http": map[string]any{
				"enabled": true,
				"host":    endpoint,
			},
		}
	}
	// indicate that beat receivers are managed by the elastic-agent
	receiverConfig["management.otel.enabled"] = true
	koanfmaps.Merge(monitoringConfig, receiverConfig)

	return map[string]any{
		receiverId.String(): receiverConfig,
	}, nil
}

// getReceiversConfigForComponent returns the exporters configuration and queue settings for a component. Usually this will be a single
// exporter, but in principle it could be more.
func getExportersConfigForComponent(comp *component.Component, logger *logp.Logger) (exporterCfg map[string]any, queueCfg map[string]any, extensionCfg map[string]any, err error) {
	exportersConfig := map[string]any{}
	extensionConfig := map[string]any{}
	exporterType, err := getExporterTypeForComponent(comp)
	if err != nil {
		return nil, nil, nil, err
	}
	var queueSettings map[string]any
	for _, unit := range comp.Units {
		if unit.Type == client.UnitTypeOutput {
			var unitExportersConfig map[string]any
			var unitExtensionConfig map[string]any
			unitExportersConfig, queueSettings, unitExtensionConfig, err = unitToExporterConfig(unit, exporterType, comp.InputType, logger)
			if err != nil {
				return nil, nil, nil, err
			}
			for k, v := range unitExportersConfig {
				exportersConfig[k] = v
			}
			for k, v := range unitExtensionConfig {
				extensionConfig[k] = v
			}
		}
	}
	return exportersConfig, queueSettings, extensionConfig, nil
}

// GetBeatNameForComponent returns the beat binary name that would be used to run this component.
func GetBeatNameForComponent(comp *component.Component) string {
	// TODO: Add this information directly to the spec?
	if comp.InputSpec == nil || comp.InputSpec.BinaryName != "agentbeat" {
		return ""
	}
	return comp.InputSpec.Spec.Command.Args[0]
}

// getSignalForComponent returns the otel signal for the given component. Currently, this is always logs, even for
// metricbeat.
func getSignalForComponent(comp *component.Component) (pipeline.Signal, error) {
	beatName := GetBeatNameForComponent(comp)
	switch beatName {
	case "filebeat", "metricbeat":
		return pipeline.SignalLogs, nil
	default:
		return pipeline.Signal{}, fmt.Errorf("unknown otel signal for input type: %s", comp.InputType)
	}
}

// getReceiverTypeForComponent returns the receiver type for the given component.
func getReceiverTypeForComponent(comp *component.Component) (otelcomponent.Type, error) {
	beatName := GetBeatNameForComponent(comp)
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
func unitToExporterConfig(unit component.Unit, exporterType otelcomponent.Type, inputType string, logger *logp.Logger) (exportersCfg map[string]any, queueSettings map[string]any, extensionCfg map[string]any, err error) {
	if unit.Type == client.UnitTypeInput {
		return nil, nil, nil, fmt.Errorf("unit type is an input, expected output: %v", unit)
	}
	configTranslationFunc, ok := configTranslationFuncForExporter[exporterType]
	if !ok {
		return nil, nil, nil, fmt.Errorf("no config translation function for exporter type: %s", exporterType)
	}
	// we'd like to use the same exporter for all outputs with the same name, so we parse out the name for the unit id
	// these will be deduplicated by the configuration merging process at the end
	outputName := strings.TrimPrefix(unit.ID, inputType+"-") // TODO: Use a more structured approach here
	exporterId := getExporterID(exporterType, outputName)

	// translate the configuration
	unitConfigMap := unit.Config.GetSource().AsMap() // this is what beats do in libbeat/management/generate.go
	outputCfgC, err := config.NewConfigFrom(unitConfigMap)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("error translating config for output: %s, unit: %s, error: %w", outputName, unit.ID, err)
	}

	// Config translation function can mutate queue settings defined under output config
	exporterConfig, err := configTranslationFunc(outputCfgC, logger)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("error translating config for output: %s, unit: %s, error: %w", outputName, unit.ID, err)
	}

	// If output config contains queue settings defined by user/preset field, it should be promoted to the receiver section
	if ok := outputCfgC.HasField("queue"); ok {
		err := outputCfgC.Unpack(&queueSettings)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("error unpacking queue settings for output: %s, unit: %s, error: %w", outputName, unit.ID, err)
		}
		if queue, ok := queueSettings["queue"].(map[string]any); ok {
			queueSettings = queue
		}
	}

	// beatsauth extension is not tested with output other than elasticsearch
	if exporterType.String() == "elasticsearch" {
		// get extension ID
		extensionID := getBeatsAuthExtensionID(outputName)
		extensionConfig, err := getBeatsAuthExtensionConfig(outputCfgC)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("error supporting http parameters for output: %s, unit: %s, error: %w", outputName, unit.ID, err)
		}

		// sets extensionCfg
		extensionCfg = map[string]any{
			extensionID.String(): extensionConfig,
		}
		// add authenticator to ES config
		exporterConfig["auth"] = map[string]any{
			"authenticator": extensionID.String(),
		}

	}

	exportersCfg = map[string]any{
		exporterId.String(): exporterConfig,
	}

	return exportersCfg, queueSettings, extensionCfg, nil
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
	beatName := GetBeatNameForComponent(comp)
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
func translateEsOutputToExporter(cfg *config.C, logger *logp.Logger) (map[string]any, error) {
	esConfig, err := ToOTelConfig(cfg, logger)
	if err != nil {
		return nil, err
	}
	// dynamic indexing works by default

	// we also want to use dynamic log ids
	esConfig["logs_dynamic_id"] = map[string]any{"enabled": true}

	// logs failed documents at debug level
	esConfig["telemetry"] = map[string]any{
		"log_failed_docs_input": true,
	}

	return esConfig, nil
}

func BeatDataPath(componentId string) string {
	return filepath.Join(paths.Run(), componentId)
}

// getBeatsAuthExtensionConfig sets http transport settings on beatsauth
// currently this is only supported for elasticsearch output
func getBeatsAuthExtensionConfig(outputCfg *config.C) (map[string]any, error) {
	defaultTransportSettings := elasticsearch.ESDefaultTransportSettings()

	var resultMap map[string]any
	if err := outputCfg.Unpack(&resultMap); err != nil {
		return nil, err
	}

	decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		Result:          &defaultTransportSettings,
		TagName:         "config",
		SquashTagOption: "inline",
		DecodeHook:      cfgDecodeHookFunc(),
	})
	if err != nil {
		return nil, err
	}

	if err = decoder.Decode(&resultMap); err != nil {
		return nil, err
	}

	newConfig, err := config.NewConfigFrom(defaultTransportSettings)
	if err != nil {
		return nil, err
	}

	// proxy_url on newConfig is of type url.URL. Beatsauth extension expects it to be of string type instead
	// this logic here converts url.URL to string type similar to what a user would set on filebeat config
	if defaultTransportSettings.Proxy.URL != nil {
		err = newConfig.SetString("proxy_url", -1, defaultTransportSettings.Proxy.URL.String())
		if err != nil {
			return nil, fmt.Errorf("error settingg proxy url:%w ", err)
		}
	}

	var newMap map[string]any
	err = newConfig.Unpack(&newMap)
	if err != nil {
		return nil, err
	}

	// required to make the extension not cause the collector to fail and exit
	// on startup
	newMap["continue_on_error"] = true

	return newMap, nil
}
