// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package configuration

import "github.com/elastic/elastic-agent/pkg/component"

type InternalConfig struct {
	Runtime *component.RuntimeConfig `yaml:"runtime" config:"runtime" json:"runtime"`
}

func DefaultInternalConfig() *InternalConfig {
	return &InternalConfig{
		Runtime: component.DefaultRuntimeConfig(),
	}
}
