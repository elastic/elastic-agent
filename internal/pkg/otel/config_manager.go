// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package otel

import (
	"context"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/coordinator"
	"github.com/elastic/elastic-agent/internal/pkg/config"
)

// OtelModeConfigManager serves as a config manager for OTel use cases
// In this case agent should ignore all configuration coming from elastic-agent.yml file
// or other sources.
type OtelModeConfigManager struct {
	ch    chan coordinator.ConfigChange
	errCh chan error
}

// NewOtelModeConfigManager creates new OtelModeConfigManager ignoring
// configuration coming from other sources.
func NewOtelModeConfigManager() *OtelModeConfigManager {
	return &OtelModeConfigManager{
		ch:    make(chan coordinator.ConfigChange),
		errCh: make(chan error),
	}
}

func (t *OtelModeConfigManager) Run(ctx context.Context) error {
	// send config to transition from STARTING to HEALTHY
	select {
	case t.ch <- &otelConfigChange{}:
	case <-ctx.Done():
	}
	<-ctx.Done()
	return ctx.Err()
}

func (t *OtelModeConfigManager) Errors() <-chan error {
	return t.errCh
}

// ActionErrors returns the error channel for actions.
// Returns nil channel.
func (t *OtelModeConfigManager) ActionErrors() <-chan error {
	return nil
}

func (t *OtelModeConfigManager) Watch() <-chan coordinator.ConfigChange {
	return t.ch
}

type otelConfigChange struct {
}

func (l *otelConfigChange) Config() *config.Config {
	return config.New()
}

func (l *otelConfigChange) Ack() error {
	// do nothing
	return nil
}

func (l *otelConfigChange) Fail(_ error) {
	// do nothing
}
