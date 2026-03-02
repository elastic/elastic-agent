// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package elasticstorage

import (
	"go.opentelemetry.io/collector/component"
)

type Config struct {
	// Hosts    []string          `mapstructure:"hosts"`
	// Protocol string            `mapstructure:"protocol"`
	// Path     string            `mapstructure:"path"`
	// Params   map[string]string `mapstructure:"parameters"`
	// Headers  map[string]string `mapstructure:"headers"`

	// Kerberos *kerberos.Config `mapstructure:"kerberos"`

	// Username string `mapstructure:"username"`
	// Password string `mapstructure:"password"`
	// APIKey   string `mapstructure:"api_key"`

	// CompressionLevel int  `mapstructure:"compression_level"`
	// EscapeHTML       bool `mapstructure:"escape_html"`

	// Transport httpcommon.HTTPTransportSettings `mapstructure:",squash"`
	ElasticsearchConfig map[string]interface{} `mapstructure:",remain"`
}

func createDefaultConfig() component.Config {
	return &Config{}
}

func (c *Config) Validate() error {
	return nil
}
