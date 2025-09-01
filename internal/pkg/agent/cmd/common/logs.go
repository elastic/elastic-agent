// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package common

import (
	"fmt"
	"strings"

	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/elastic-agent-libs/logp/configure"
	"github.com/elastic/elastic-agent/internal/pkg/agent/configuration"
	"github.com/elastic/elastic-agent/internal/pkg/release"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

func ConfiguredLogger(cfg *configuration.Configuration, name string) (*logger.Logger, error) {
	cfg.Settings.LoggingConfig.Beat = name
	cfg.Settings.LoggingConfig.Level = logp.DebugLevel
	internal, err := logger.MakeInternalFileOutput(cfg.Settings.LoggingConfig)
	if err != nil {
		return nil, err
	}

	libC, err := logger.ToCommonConfig(cfg.Settings.LoggingConfig)
	if err != nil {
		return nil, err
	}

	if err := configure.LoggingWithOutputs("", libC, internal); err != nil {
		return nil, fmt.Errorf("error initializing logging: %w", err)
	}
	return logp.NewLogger(""), nil
}

func TroubleshootMessage() string {
	v := strings.Split(release.Version(), ".")
	version := strings.Join(v[:2], ".")
	return fmt.Sprintf("For help, please see our troubleshooting guide at https://www.elastic.co/guide/en/fleet/%s/fleet-troubleshooting.html", version)
}
