// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package elasticdiagnosticsextension

import (
	"errors"

	"go.opentelemetry.io/collector/component"
)

type Config struct {
	Host    string `mapstructure:"host"`
	Network string `mapstructure:"network"`
}

func createDefaultConfig() component.Config {
	return &Config{
		Network: "unix",
	}
}

func (c *Config) Validate() error {
	if c.Host == "" {
		return errors.New("hosts is a required field")
	}
	return nil
}
