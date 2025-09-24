// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package elasticdiagnostics

import (
	"errors"

	"go.opentelemetry.io/collector/component"
)

type Config struct {
	Endpoint string `mapstructure:"endpoint"`
}

func createDefaultConfig() component.Config {
	return &Config{}
}

func (c *Config) Validate() error {
	if c.Endpoint == "" {
		return errors.New("endpoint is a required field")
	}
	return nil
}
