// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package application

import (
	"context"
	"time"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/coordinator"
	"github.com/elastic/elastic-agent/internal/pkg/config"
	"github.com/elastic/elastic-agent/pkg/component"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

// injectFleetServerInput is the base configuration that is used plus the FleetServerComponentModifier that adjusts
// the components before sending them to the runtime manager.
var injectFleetServerInput = config.MustNewConfigFrom(map[string]interface{}{
	"outputs": map[string]interface{}{
		"default": map[string]interface{}{
			"type":  "elasticsearch",
			"hosts": []string{"localhost:9200"},
		},
	},
	"inputs": []interface{}{
		map[string]interface{}{
			"type": "fleet-server",
		},
	},
})

// FleetServerComponentModifier modifies the comps to inject extra information from the policy into
// the Fleet Server component and units needed to run Fleet Server correctly.
func FleetServerComponentModifier(comps []component.Component, policy map[string]interface{}) ([]component.Component, error) {
	return comps, nil
}

type fleetServerBootstrapManager struct {
	log *logger.Logger

	ch    chan coordinator.ConfigChange
	errCh chan error
}

func newFleetServerBootstrapManager(
	log *logger.Logger,
) (*fleetServerBootstrapManager, error) {
	return &fleetServerBootstrapManager{
		log:   log,
		ch:    make(chan coordinator.ConfigChange),
		errCh: make(chan error),
	}, nil
}

func (m *fleetServerBootstrapManager) Run(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	m.log.Debugf("injecting fleet-server for bootstrap")
	select {
	case <-ctx.Done():
		return ctx.Err()
	case m.ch <- &localConfigChange{injectFleetServerInput}:
	}

	<-ctx.Done()
	return ctx.Err()
}

func (m *fleetServerBootstrapManager) Errors() <-chan error {
	return m.errCh
}

func (m *fleetServerBootstrapManager) Watch() <-chan coordinator.ConfigChange {
	return m.ch
}
