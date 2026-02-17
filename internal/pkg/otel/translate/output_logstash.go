// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package translate

import (
	"fmt"

	"github.com/go-viper/mapstructure/v2"

	"github.com/elastic/beats/v7/libbeat/outputs"
	"github.com/elastic/beats/v7/libbeat/outputs/logstash"
	"github.com/elastic/elastic-agent-libs/config"
	"github.com/elastic/elastic-agent-libs/logp"
)

type logstashOutputConfig struct {
	outputs.HostWorkerCfg `config:",inline"`
	logstash.Config       `config:",inline"`
}

// LogstashToOTelConfig converts a Beat config into logstash exporter config
// Note: This method may override output queue settings defined by user.
func LogstashToOTelConfig(output *config.C, logger *logp.Logger) (map[string]any, error) {
	logstashConfig := logstashOutputConfig{
		Config: logstash.DefaultConfig(),
	}

	// this step is only to return any validation errors
	if err := output.Unpack(&logstashConfig); err != nil {
		return nil, fmt.Errorf("failed unpacking config. %w", err)
	}

	// unpack the config again into a map so that we can decode it using mapstructure with our custom decode hook
	unpackedMap := make(map[string]any)
	if err := output.Unpack(&unpackedMap); err != nil {
		return nil, fmt.Errorf("failed unpacking config. %w", err)
	}

	decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		Result:          &logstashConfig,
		TagName:         "config",
		SquashTagOption: "inline",
		DecodeHook:      cfgDecodeHookFunc(),
	})
	if err != nil {
		return nil, fmt.Errorf("failed creating decoder. %w", err)
	}

	err = decoder.Decode(&unpackedMap)
	if err != nil {
		return nil, fmt.Errorf("failed decoding config. %w", err)
	}

	// convert logstash config into a map
	var finalMap map[string]any
	lsConfig := config.MustNewConfigFrom(logstashConfig)
	if err := lsConfig.Unpack(&finalMap); err != nil {
		return nil, fmt.Errorf("error translating logstash config %w", err)
	}

	return finalMap, nil
}
