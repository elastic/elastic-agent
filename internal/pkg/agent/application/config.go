// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package application

import (
	"github.com/elastic/elastic-agent/internal/pkg/agent/configuration"
)

type localConfig struct {
	Fleet    *configuration.FleetAgentConfig `config:"fleet"`
	Settings *configuration.SettingsConfig   `config:"agent" yaml:"agent"`
}
