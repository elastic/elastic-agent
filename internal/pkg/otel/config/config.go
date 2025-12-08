// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package config

import (
	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/elastic-agent/internal/pkg/config"
)

const (
	defaultExecMode = SubprocessExecutionMode

	SubprocessExecutionMode ExecutionMode = "subprocess"
	EmbeddedExecutionMode   ExecutionMode = "embedded"
)

type ExecutionMode string

type execModeConfig struct {
	Agent struct {
		Features struct {
			Otel *struct {
				SubprocessExecution *bool `json:"subprocess_execution,omitempty" yaml:"subprocess_execution,omitempty" config:"subprocess_execution,omitempty"`
			} `json:"otel,omitempty" yaml:"otel,omitempty" config:"otel,omitempty"`
		} `json:"features" yaml:"features" config:"features"`
	} `json:"agent" yaml:"agent" config:"agent"`
}

// GetExecutionModeFromConfig returns the execution mode of the OTel runtime based on the config.
func GetExecutionModeFromConfig(log *logp.Logger, conf *config.Config) ExecutionMode {
	var c execModeConfig
	if err := conf.UnpackTo(&c); err != nil {
		log.Warnf("failed to unpack config when getting otel runtime execution mode: %v", err)
		return defaultExecMode
	}

	if c.Agent.Features.Otel == nil {
		return defaultExecMode
	}

	if c.Agent.Features.Otel.SubprocessExecution == nil {
		return defaultExecMode
	}

	if *c.Agent.Features.Otel.SubprocessExecution {
		return SubprocessExecutionMode
	} else {
		return EmbeddedExecutionMode
	}
}
