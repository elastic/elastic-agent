// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package otel

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetOtelDependencies(t *testing.T) {
	goModContent := `module github.com/elastic/elastic-agent

go 1.24.1

require (
	github.com/elastic/opentelemetry-collector-components/connector/signaltometricsconnector v0.3.0
	github.com/open-telemetry/opentelemetry-collector-contrib/connector/routingconnector v0.119.0
	github.com/open-telemetry/opentelemetry-collector-contrib/exporter/kafkaexporter v0.119.0
	github.com/open-telemetry/opentelemetry-collector-contrib/processor/transformprocessor v0.119.0
	github.com/open-telemetry/opentelemetry-collector-contrib/extension/healthcheckextension v0.119.0
	github.com/open-telemetry/opentelemetry-collector-contrib/pkg/status v0.119.0
	github.com/open-telemetry/opentelemetry-collector-contrib/receiver/kafkareceiver v0.119.0
	github.com/open-telemetry/opentelemetry-collector-contrib/receiver/prometheusreceiver v0.119.0
	go.opentelemetry.io/collector/component/componentstatus v0.119.0
	go.opentelemetry.io/collector/confmap/provider/envprovider v1.25.0
	go.opentelemetry.io/collector/exporter/debugexporter v0.119.0
	go.opentelemetry.io/collector/extension/memorylimiterextension v0.119.0
	go.opentelemetry.io/collector/processor/batchprocessor v0.119.0
	go.opentelemetry.io/collector/receiver/otlpreceiver v0.119.0
	golang.org/x/crypto v0.36.0
	github.com/elastic/elastic-agent-autodiscover v0.9.0
)
require (
	cel.dev/expr v0.19.1 // indirect
	github.com/open-telemetry/opentelemetry-collector-contrib/extension/observer v0.119.0 // indirect
	go.opentelemetry.io/collector v0.119.0 // indirect
	go.opentelemetry.io/collector/exporter/exporterhelper/xexporterhelper v0.119.0 // indirect
	go.opentelemetry.io/collector/extension/auth v0.119.0 // indirect
	go.opentelemetry.io/collector/processor/processorhelper/xprocessorhelper v0.119.0 // indirect
	go.opentelemetry.io/collector/receiver/xreceiver v0.119.0 // indirect
)

replace (
	github.com/fsnotify/fsnotify => github.com/elastic/fsnotify v1.6.1-0.20240920222514-49f82bdbc9e3
	github.com/open-telemetry/opentelemetry-collector-contrib/receiver/prometheusreceiver v0.119.0 => github.com/elastic/opentelemetry-collector-contrib/receiver/prometheusreceiver v0.0.0-20250317163643-19cd4e80024f
)

`
	tempGoModFile := filepath.Join(os.TempDir(), "go.mod")
	err := os.WriteFile(tempGoModFile, []byte(goModContent), 0600)
	require.NoError(t, err)
	t.Cleanup(func() {
		removeErr := os.Remove(tempGoModFile)
		assert.NoError(t, removeErr)
	})

	expected := &OtelDependencies{
		Connectors: []*otelDependency{
			{
				ComponentType: "connector",
				Name:          "routingconnector",
				Version:       "v0.119.0",
				Link:          "https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/connector/routingconnector/v0.119.0/connector/routingconnector/README.md",
			},
			{
				ComponentType: "connector",
				Name:          "signaltometricsconnector",
				Version:       "v0.3.0",
				Link:          "https://github.com/elastic/opentelemetry-collector-components/blob/connector/signaltometricsconnector/v0.3.0/connector/signaltometricsconnector/README.md",
			},
		},
		Exporters: []*otelDependency{
			{
				ComponentType: "exporter",
				Name:          "debugexporter",
				Version:       "v0.119.0",
				Link:          "https://github.com/open-telemetry/opentelemetry-collector/blob/exporter/debugexporter/v0.119.0/exporter/debugexporter/README.md",
			},
			{
				ComponentType: "exporter",
				Name:          "kafkaexporter",
				Version:       "v0.119.0",
				Link:          "https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/exporter/kafkaexporter/v0.119.0/exporter/kafkaexporter/README.md",
			},
		},
		Extensions: []*otelDependency{
			{
				ComponentType: "extension",
				Name:          "healthcheckextension",
				Version:       "v0.119.0",
				Link:          "https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/extension/healthcheckextension/v0.119.0/extension/healthcheckextension/README.md",
			},
			{
				ComponentType: "extension",
				Name:          "memorylimiterextension",
				Version:       "v0.119.0",
				Link:          "https://github.com/open-telemetry/opentelemetry-collector/blob/extension/memorylimiterextension/v0.119.0/extension/memorylimiterextension/README.md",
			},
		},
		Processors: []*otelDependency{
			{
				ComponentType: "processor",
				Name:          "batchprocessor",
				Version:       "v0.119.0",
				Link:          "https://github.com/open-telemetry/opentelemetry-collector/blob/processor/batchprocessor/v0.119.0/processor/batchprocessor/README.md",
			},
			{
				ComponentType: "processor",
				Name:          "transformprocessor",
				Version:       "v0.119.0",
				Link:          "https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/processor/transformprocessor/v0.119.0/processor/transformprocessor/README.md",
			},
		},
		Receivers: []*otelDependency{
			{
				ComponentType: "receiver",
				Name:          "kafkareceiver",
				Version:       "v0.119.0",
				Link:          "https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/receiver/kafkareceiver/v0.119.0/receiver/kafkareceiver/README.md",
			},
			{
				ComponentType: "receiver",
				Name:          "otlpreceiver",
				Version:       "v0.119.0",
				Link:          "https://github.com/open-telemetry/opentelemetry-collector/blob/receiver/otlpreceiver/v0.119.0/receiver/otlpreceiver/README.md",
			},
			{
				ComponentType: "receiver",
				Name:          "prometheusreceiver",
				Version:       "v0.0.0-20250317163643-19cd4e80024f",
				Link:          "https://github.com/elastic/opentelemetry-collector-contrib/blob/19cd4e80024f/receiver/prometheusreceiver/README.md",
			},
		},
	}

	actual, err := GetOtelDependencies(tempGoModFile)
	require.NoError(t, err)
	assert.EqualExportedValues(t, expected, actual)
}
