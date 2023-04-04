// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package application

import (
	"context"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/coordinator"
	"github.com/elastic/elastic-agent/internal/pkg/config"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

type testingModeConfigManager struct {
	log   *logger.Logger
	ch    chan coordinator.ConfigChange
	errCh chan error
}

func newTestingModeConfigManager(log *logger.Logger) *testingModeConfigManager {
	return &testingModeConfigManager{
		log:   log,
		ch:    make(chan coordinator.ConfigChange),
		errCh: make(chan error),
	}
}

func (t *testingModeConfigManager) Run(ctx context.Context) error {
	<-ctx.Done()
	return ctx.Err()
}

func (t *testingModeConfigManager) Errors() <-chan error {
	return t.errCh
}

// ActionErrors returns the error channel for actions.
// Returns nil channel.
func (t *testingModeConfigManager) ActionErrors() <-chan error {
	return nil
}

func (t *testingModeConfigManager) Watch() <-chan coordinator.ConfigChange {
	return t.ch
}

func (t *testingModeConfigManager) SetConfig(ctx context.Context, cfg string) error {
	rawConfig, err := config.NewConfigFrom(cfg)
	if err != nil {
		return err
	}
	t.log.Info("Testing mode received new configuration from protocol, passing to coordinator")
	select {
	case <-ctx.Done():
		return ctx.Err()
	case t.ch <- &localConfigChange{rawConfig}:
	}
	return nil
}
