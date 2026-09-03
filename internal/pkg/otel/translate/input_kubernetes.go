// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package translate

import (
	"fmt"
	"maps"
	"slices"

	"github.com/elastic/elastic-agent-libs/logp"

	otelcomponent "go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/confmap"
	"go.opentelemetry.io/collector/pipeline"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
	k8sutil "github.com/elastic/elastic-agent/internal/pkg/otel/k8s"
	"github.com/elastic/elastic-agent/pkg/component"
)

// IsKubernetesContainerLogComponent reports whether comp represents a
// kubernetes container-logs filestream input that the native filelog receiver
// can replace. Exported so the coordinator can check components before
// splitting the model between managers.
func IsKubernetesContainerLogComponent(comp *component.Component) bool {
	return k8sutil.IsContainerLogComponent(comp)
}

// getKubernetesContainerLogConfig generates a complete OTel collector config for a
// kubernetes container-log component using a native filelog receiver instead of a
// filebeatreceiver. The generated config includes:
//   - A single filelog receiver watching /var/log/pods (or the configured paths)
//   - A k8sattributes processor for Kubernetes metadata enrichment
//   - An OTTL transform processor setting ECS mapping mode and static fields
//   - The component's existing exporter (elasticsearch / logstash / kafka)
func getKubernetesContainerLogConfig(
	comp *component.Component,
	agentInfo info.Agent,
	logger *logp.Logger,
) (*confmap.Conf, error) {
	exporterType, err := OutputTypeToExporterType(comp.OutputType)
	if err != nil {
		return nil, err
	}
	exporterID := GetExporterID(exporterType, comp.OutputName)
	exporterConfig, _, extensionConfig, processorConfig, err := getExporterConfigForComponent(comp, exporterType, logger)
	if err != nil {
		return nil, err
	}

	receiverID := k8sFilelogReceiverID(comp)
	receiverConfig := k8sutil.BuildFilelogReceiverConfig(comp)

	ecsModeTransformID := ecsMappingTransformProcessorID(comp)
	ecsModeTransformConfig := k8sutil.BuildEcsMappingTransformConfig(agentInfo)

	k8sAttrProcessorID := k8sAttributesProcessorID(comp)
	k8sAttrProcessorConfig := k8sutil.BuildK8sAttributesProcessorConfig()

	pipelineID := pipeline.NewIDWithName(pipeline.SignalLogs, fmt.Sprintf("%s%s", OtelNamePrefix, comp.ID))

	// k8sattributes must run before the transform so that attributes added by
	// k8sattributes (e.g. k8s.pod.start_time) are available for renaming.
	pipelineProcessors := []string{k8sAttrProcessorID.String(), ecsModeTransformID.String()}

	outputProcessors, err := extractOtelProcessors(comp)
	if err != nil {
		return nil, fmt.Errorf("could not read per-output processor: %w", err)
	}
	pipelineProcessors = append(pipelineProcessors, outputProcessors...)

	if len(processorConfig) != 0 {
		if len(processorConfig) > 1 {
			return nil, fmt.Errorf("found more than one processor config")
		}
		pipelineProcessors = slices.AppendSeq(pipelineProcessors, maps.Keys(processorConfig))
	}

	pipelineConfig := map[string]any{
		"receivers":  []string{receiverID.String()},
		"processors": pipelineProcessors,
		"exporters":  []string{exporterID.String()},
	}

	allProcessors := map[string]any{
		ecsModeTransformID.String():  ecsModeTransformConfig,
		k8sAttrProcessorID.String(): k8sAttrProcessorConfig,
	}
	maps.Copy(allProcessors, processorConfig)

	fullConfig := map[string]any{
		"receivers": map[string]any{
			receiverID.String(): receiverConfig,
		},
		"processors": allProcessors,
		"exporters": map[string]any{
			exporterID.String(): exporterConfig,
		},
		"service": map[string]any{
			"pipelines": map[string]any{
				pipelineID.String(): pipelineConfig,
			},
		},
	}

	if extensionConfig != nil {
		extensionKeys := make([]any, 0, len(extensionConfig))
		for k := range extensionConfig {
			extensionKeys = append(extensionKeys, k)
		}
		fullConfig["extensions"] = extensionConfig
		fullConfig["service"] = map[string]any{
			"extensions": extensionKeys,
			"pipelines": map[string]any{
				pipelineID.String(): pipelineConfig,
			},
		}
	}

	return confmap.NewFromStringMap(fullConfig), nil
}

func ecsMappingTransformProcessorID(comp *component.Component) otelcomponent.ID {
	name := fmt.Sprintf("%s%s", OtelNamePrefix, comp.ID)
	return otelcomponent.NewIDWithName(otelcomponent.MustNewType("transform"), name)
}

func k8sFilelogReceiverID(comp *component.Component) otelcomponent.ID {
	return GetReceiverID(otelcomponent.MustNewType("filelog"), comp.ID)
}

func k8sAttributesProcessorID(comp *component.Component) otelcomponent.ID {
	name := fmt.Sprintf("%s%s", OtelNamePrefix, comp.ID)
	return otelcomponent.NewIDWithName(otelcomponent.MustNewType("k8sattributes"), name)
}
