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

	"github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/monitoring/monitoringhelpers"

	"github.com/elastic/elastic-agent-libs/logp"

	otelcomponent "go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/confmap"
	"go.opentelemetry.io/collector/pipeline"
	"golang.org/x/exp/maps"

	"github.com/elastic/beats/v7/libbeat/outputs/elasticsearch"
	"github.com/elastic/beats/v7/x-pack/libbeat/management"
	"github.com/elastic/beats/v7/x-pack/otel/extension/beatsauthextension"
	"github.com/elastic/elastic-agent-libs/config"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/pkg/component"
	"github.com/elastic/elastic-agent/pkg/component/runtime"
)

// This is a prefix we add to all names of Otel entities in the configuration. Its purpose is to avoid collisions with
// user-provided configuration
const (
	OtelNamePrefix                        = "_agent-component/"
	BeatsAuthExtensionType                = "beatsauth"
	outputOtelOverrideFieldName           = "otel"
	outputOtelOverrideExporterFieldName   = "exporter"
	outputOtelOverrideExtensionsFieldName = "extensions"
)

// BeatMonitoringConfigGetter is a function that returns the monitoring configuration for a beat receiver.
type (
	BeatMonitoringConfigGetter    func(unitID, binary string) map[string]any
	exporterConfigTranslationFunc func(*config.C, *logp.Logger) (map[string]any, error)
)

var (
	OtelSupportedOutputTypes         = []string{"elasticsearch"}
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

func LogpLevelToOTel(lvl logp.Level) (string, error) {
	switch lvl {
	case logp.DebugLevel:
		return "DEBUG", nil
	case logp.InfoLevel:
		return "INFO", nil
	case logp.WarnLevel:
		return "WARN", nil
	case logp.ErrorLevel:
		return "ERROR", nil
	default:
		return "UNKNOWN", fmt.Errorf("unknown logp level: %s", lvl)
	}
}

func OTelLevelToLogp(lvl string) (logp.Level, error) {
	switch strings.ToUpper(lvl) {
	case "DEBUG":
		return logp.DebugLevel, nil
	case "INFO":
		return logp.InfoLevel, nil
	case "WARN":
		return logp.WarnLevel, nil
	case "ERROR":
		return logp.ErrorLevel, nil
	default:
		return logp.Level(-128), fmt.Errorf("unknown otel level: %s", lvl)
	}
}

// VerifyComponentIsOtelSupported verifies that the given component can be run in an Otel Collector. It returns an error
// indicating what the problem is, if it can't.
func VerifyComponentIsOtelSupported(comp *component.Component) error {
	if !slices.Contains(OtelSupportedOutputTypes, comp.OutputType) {
		return fmt.Errorf("unsupported output type: %s", comp.OutputType)
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

// VerifyOutputIsOtelSupported verifies that the given output can be converted into an Otel Collector exporter. It
// returns an error indicating what the problem is, if it can't.
func VerifyOutputIsOtelSupported(outputType string, outputCfg map[string]any) error {
	if !slices.Contains(OtelSupportedOutputTypes, outputType) {
		return fmt.Errorf("unsupported output type: %s", outputType)
	}
	exporterType, err := OutputTypeToExporterType(outputType)
	if err != nil {
		return err
	}

	outputCfgC, err := config.NewConfigFrom(outputCfg)
	if err != nil {
		return err
	}

	_, err = OutputConfigToExporterConfig(logp.NewNopLogger(), exporterType, outputCfgC)
	if errors.Is(err, errors.ErrUnsupported) {
		return fmt.Errorf("unsupported configuration for %s: %w", outputType, err)
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

// GetReceiverID returns the receiver id for the given unit and exporter type.
func GetReceiverID(receiverType otelcomponent.Type, unitID string) otelcomponent.ID {
	receiverName := fmt.Sprintf("%s%s", OtelNamePrefix, unitID)
	return otelcomponent.NewIDWithName(receiverType, receiverName)
}

// GetExporterID returns the exporter id for the given exporter type and output name.
func GetExporterID(exporterType otelcomponent.Type, outputName string) otelcomponent.ID {
	exporterName := fmt.Sprintf("%s%s", OtelNamePrefix, outputName)
	return otelcomponent.NewIDWithName(exporterType, exporterName)
}

// getBeatsAuthExtensionID returns the id for beatsauth extension
// outputName here is name of the output defined in elastic-agent.yml. For ex: default, monitoring
func getBeatsAuthExtensionID(outputName string) otelcomponent.ID {
	extensionName := fmt.Sprintf("%s%s", OtelNamePrefix, outputName)
	return otelcomponent.NewIDWithName(otelcomponent.MustNewType(BeatsAuthExtensionType), extensionName)
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
	exporterType, err := OutputTypeToExporterType(comp.OutputType)
	if err != nil {
		return nil, err
	}
	exporterID := GetExporterID(exporterType, comp.OutputName)
	exporterConfig, outputQueueConfig, extensionConfig, err := getExporterConfigForComponent(comp, exporterType, logger)
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
			"exporters": []string{exporterID.String()},
			"receivers": maps.Keys(receiversConfig),
		},
	}

	// we need to convert []string to []interface for this to work
	extensionKey := make([]any, len(maps.Keys(extensionConfig)))
	for i, v := range maps.Keys(extensionConfig) {
		extensionKey[i] = v
	}

	fullConfig := map[string]any{
		"receivers": receiversConfig,
		"exporters": map[string]any{
			exporterID.String(): exporterConfig,
		},
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

	receiverId := GetReceiverID(receiverType, comp.ID)
	// Beat config inside a beat receiver is nested under an additional key. Not sure if this simple translation is
	// always safe. We should either ensure this is always the case, or have an explicit mapping.
	beatName := strings.TrimSuffix(receiverType.String(), "receiver")
	binaryName := comp.BeatName()
	dataset := fmt.Sprintf("elastic_agent.%s", strings.ReplaceAll(strings.ReplaceAll(binaryName, "-", "_"), "/", "_"))

	receiverConfig := map[string]any{
		// just like we do for beats processes, each receiver needs its own data path
		"path": map[string]any{
			"home": paths.Components(),
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

	// Explicitly configure default processors for Beat receivers.
	receiverConfig["processors"] = getDefaultProcessors(beatName)

	// add monitoring config if necessary
	// we enable the basic monitoring endpoint by default, because we want to use it for diagnostics even if
	// agent self-monitoring is disabled
	var monitoringConfig map[string]any
	if beatMonitoringConfigGetter != nil {
		monitoringConfig = beatMonitoringConfigGetter(comp.ID, beatName)
	}

	if monitoringConfig == nil {
		endpoint := monitoringhelpers.BeatsMonitoringEndpoint(comp.ID)
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

func getDefaultProcessors(beatName string) []map[string]any {
	addHostMetadata := map[string]any{
		"add_host_metadata": nil,
	}
	if beatName == "filebeat" {
		addHostMetadata["add_host_metadata"] = map[string]any{
			"when.not.contains.tags": "forwarded",
		}
	}

	return []map[string]any{
		addHostMetadata,
		{"add_cloud_metadata": nil},
		{"add_docker_metadata": nil},
		{"add_kubernetes_metadata": nil},
	}
}

// getExporterConfigForComponent returns the exporter configuration and queue settings for a component. Note that a
// valid component is always created from a single output config, so there should only be one output unit per
// component; if there is more than one, this function returns the first.
func getExporterConfigForComponent(comp *component.Component, exporterType otelcomponent.Type, logger *logp.Logger) (exporterCfg map[string]any, queueCfg map[string]any, extensionCfg map[string]any, err error) {
	for _, unit := range comp.Units {
		if unit.Type == client.UnitTypeOutput {
			return unitToExporterConfig(unit, comp.OutputName, exporterType, logger)
		}
	}
	return nil, nil, nil, nil
}

// getSignalForComponent returns the otel signal for the given component. Currently, this is always logs, even for
// metricbeat.
func getSignalForComponent(comp *component.Component) (pipeline.Signal, error) {
	beatName := comp.BeatName()
	switch beatName {
	case "filebeat", "metricbeat":
		return pipeline.SignalLogs, nil
	default:
		return pipeline.Signal{}, fmt.Errorf("unknown otel signal for input type: %s", comp.InputType)
	}
}

// getReceiverTypeForComponent returns the receiver type for the given component.
func getReceiverTypeForComponent(comp *component.Component) (otelcomponent.Type, error) {
	beatName := comp.BeatName()
	switch beatName {
	case "filebeat":
		return otelcomponent.MustNewType("filebeatreceiver"), nil
	case "metricbeat":
		return otelcomponent.MustNewType("metricbeatreceiver"), nil
	default:
		return otelcomponent.Type{}, fmt.Errorf("unknown otel receiver type for input type: %s", comp.InputType)
	}
}

// OutputTypeToExporterType returns the exporter type for the given output type.
func OutputTypeToExporterType(outputType string) (otelcomponent.Type, error) {
	switch outputType {
	case "elasticsearch":
		return otelcomponent.MustNewType("elasticsearch"), nil
	default:
		return otelcomponent.Type{}, fmt.Errorf("unknown otel exporter type for output type: %s", outputType)
	}
}

// unitToExporterConfig translates a component.Unit to return an otel exporter configuration and output queue settings
func unitToExporterConfig(unit component.Unit, outputName string, exporterType otelcomponent.Type, logger *logp.Logger) (exportersCfg map[string]any, queueSettings map[string]any, extensionCfg map[string]any, err error) {
	if unit.Type == client.UnitTypeInput {
		return nil, nil, nil, fmt.Errorf("unit type is an input, expected output: %v", unit)
	}

	// translate the configuration
	unitConfigMap := unit.Config.GetSource().AsMap() // this is what beats do in libbeat/management/generate.go
	outputCfgC, err := config.NewConfigFrom(unitConfigMap)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("error translating config for output: %s, unit: %s, error: %w", outputName, unit.ID, err)
	}

	// if there's an otel override config, extract it, we'll apply it after the conversion
	otelOverrideCfgC, err := extractOutputOtelOverrideConfig(outputCfgC)
	if err != nil {
		return nil, nil, nil, err
	}

	// Config translation function can mutate queue settings defined under output config
	exporterConfig, err := OutputConfigToExporterConfig(logger, exporterType, outputCfgC)
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

	// if there's an otel override section for the exporter, we should apply it
	exporterOverrideCfg, err := getOutputOtelOverrideExporterConfig(otelOverrideCfgC)
	if err != nil {
		return nil, nil, nil, err
	}
	koanfmaps.Merge(exporterOverrideCfg, exporterConfig)

	// if there's an otel override section for extensions, extract it and apply it to individual extension configs
	extensionsOverrideCfg, err := getOutputOtelOverrideExtensionsConfig(otelOverrideCfgC)
	if err != nil {
		return nil, nil, nil, err
	}

	// beatsauth extension is not tested with output other than elasticsearch
	if exporterType.String() == "elasticsearch" {
		// get extension ID
		extensionID := getBeatsAuthExtensionID(outputName)
		extensionConfig, err := getBeatsAuthExtensionConfig(outputCfgC)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("error supporting http parameters for output: %s, unit: %s, error: %w", outputName, unit.ID, err)
		}

		if beatsauthOverrideCfg, found := extensionsOverrideCfg[BeatsAuthExtensionType]; found {
			koanfmaps.Merge(beatsauthOverrideCfg, extensionConfig)
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

	return exporterConfig, queueSettings, extensionCfg, nil
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

// OutputConfigToExporterConfig translates the output configuration to an exporter configuration.
func OutputConfigToExporterConfig(logger *logp.Logger, exporterType otelcomponent.Type, outputConfig *config.C) (map[string]any, error) {
	configTranslationFunc, ok := configTranslationFuncForExporter[exporterType]
	if !ok {
		return nil, fmt.Errorf("no config translation function for exporter type: %s", exporterType)
	}

	exporterConfig, err := configTranslationFunc(outputConfig, logger)
	if err != nil {
		return nil, err
	}

	return exporterConfig, nil
}

// getDefaultDatastreamTypeForComponent returns the default datastream type for a given component.
// This is needed to translate from the agent policy config format to the beats config format.
func getDefaultDatastreamTypeForComponent(comp *component.Component) (string, error) {
	beatName := comp.BeatName()
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

	// we want to use dynamic log ids
	esConfig["logs_dynamic_id"] = map[string]any{"enabled": true}

	esConfig["include_source_on_error"] = true

	return esConfig, nil
}

// extractOutputOtelOverrideConfig removes the configuration under the otel override key from the provided configuration
// and returns it.
func extractOutputOtelOverrideConfig(cfg *config.C) (*config.C, error) {
	if !cfg.HasField(outputOtelOverrideFieldName) {
		return nil, nil
	}
	otelCfg, err := cfg.Child(outputOtelOverrideFieldName, -1)
	if err != nil {
		return nil, err
	}
	_, err = cfg.Remove(outputOtelOverrideFieldName, -1)
	if err != nil {
		return nil, err
	}
	return otelCfg, nil
}

// getOutputOtelOverrideExporterConfig returns the exporter override configuration from the given otel override
// configuration as a map[string]any. It does not modify the input.
func getOutputOtelOverrideExporterConfig(otelOverrideCfg *config.C) (map[string]any, error) {
	if otelOverrideCfg == nil {
		return nil, nil
	}
	if !otelOverrideCfg.HasField(outputOtelOverrideExporterFieldName) {
		return nil, nil
	}
	exporterCfgC, err := otelOverrideCfg.Child(outputOtelOverrideExporterFieldName, -1)
	if err != nil {
		return nil, err
	}
	exporterCfgMap := make(map[string]any)
	err = exporterCfgC.Unpack(&exporterCfgMap)
	if err != nil {
		return nil, err
	}
	return exporterCfgMap, nil
}

// getOutputOtelOverrideExporterConfig returns the override configuration for extensions from the given otel override
// configuration. The return value is a map keyed by extension types, with configuration overrides as values.
func getOutputOtelOverrideExtensionsConfig(otelOverrideCfg *config.C) (map[string]map[string]any, error) {
	if otelOverrideCfg == nil {
		return nil, nil
	}
	if !otelOverrideCfg.HasField(outputOtelOverrideExtensionsFieldName) {
		return nil, nil
	}
	extensionsCfgC, err := otelOverrideCfg.Child(outputOtelOverrideExtensionsFieldName, -1)
	if err != nil {
		return nil, err
	}
	extensionsCfgMap := make(map[string]map[string]any)
	err = extensionsCfgC.Unpack(&extensionsCfgMap)
	if err != nil {
		return nil, err
	}
	return extensionsCfgMap, nil
}

func BeatDataPath(componentId string) string {
	return filepath.Join(paths.Run(), componentId)
}

// getBeatsAuthExtensionConfig sets http transport settings on beatsauth
// currently this is only supported for elasticsearch output
func getBeatsAuthExtensionConfig(outputCfg *config.C) (map[string]any, error) {
	authSettings := beatsauthextension.BeatsAuthConfig{
		Transport: elasticsearch.ESDefaultTransportSettings(),
	}

	var resultMap map[string]any
	if err := outputCfg.Unpack(&resultMap); err != nil {
		return nil, err
	}

	decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		Result:          &authSettings,
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

	newConfig, err := config.NewConfigFrom(authSettings)
	if err != nil {
		return nil, err
	}

	// proxy_url on newConfig is of type url.URL. Beatsauth extension expects it to be of string type instead
	// this logic here converts url.URL to string type similar to what a user would set on filebeat config
	if authSettings.Transport.Proxy.URL != nil {
		err = newConfig.SetString("proxy_url", -1, authSettings.Transport.Proxy.URL.String())
		if err != nil {
			return nil, fmt.Errorf("error settingg proxy url:%w ", err)
		}
	}

	if authSettings.Kerberos != nil {
		err = newConfig.SetString("kerberos.auth_type", -1, authSettings.Kerberos.AuthType.String())
		if err != nil {
			return nil, fmt.Errorf("error setting kerberos auth type url:%w ", err)
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
