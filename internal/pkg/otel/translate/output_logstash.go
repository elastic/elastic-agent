// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package translate

import (
	"fmt"

	otelcomponent "go.opentelemetry.io/collector/component"

	"github.com/elastic/beats/v7/libbeat/outputs"
	"github.com/elastic/beats/v7/libbeat/outputs/logstash"
	"github.com/elastic/beats/v7/pkg/config"
	"github.com/elastic/beats/v7/pkg/logp"
)

type logstashOutputConfig struct {
	outputs.HostWorkerCfg `config:",inline"`
	logstash.Config       `config:",inline"`
}

// LogstashToOTelConfig converts a Beat config into logstash exporter config
func LogstashToOTelConfig(output *config.C, outputName string, logger *logp.Logger) (TranslatedOutput, error) {
	logstashConfig := logstashOutputConfig{
		Config: logstash.DefaultConfig(),
	}

	// unpack and validate lsConfig
	if err := output.Unpack(&logstashConfig); err != nil {
		return TranslatedOutput{}, fmt.Errorf("failed unpacking config. %w", err)
	}

	// convert logstash config into a map
	var finalMap map[string]any
	lsConfig := config.MustNewConfigFrom(logstashConfig)
	if err := lsConfig.Unpack(&finalMap); err != nil {
		return TranslatedOutput{}, fmt.Errorf("error translating logstash config %w", err)
	}

	exporterCfg := map[string]any{
		GetExporterID(otelcomponent.MustNewType("logstash"), outputName).String(): finalMap,
	}

	return TranslatedOutput{Exporters: exporterCfg}, nil
}
