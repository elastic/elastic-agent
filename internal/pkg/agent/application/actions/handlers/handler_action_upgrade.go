// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package handlers

import (
	"context"
	"fmt"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/coordinator"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi/acker"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

// Upgrade is a handler for UPGRADE action.
// After running Upgrade agent should download its own version specified by action
// from repository specified by fleet.
type Upgrade struct {
	log   *logger.Logger
	coord *coordinator.Coordinator
}

// NewUpgrade creates a new Upgrade handler.
func NewUpgrade(log *logger.Logger, coord *coordinator.Coordinator) *Upgrade {
	return &Upgrade{
		log:   log,
		coord: coord,
	}
}

// Handle handles UPGRADE action.
func (h *Upgrade) Handle(ctx context.Context, a fleetapi.Action, _ acker.Acker) error {
	h.log.Debugf("handlerUpgrade: action '%+v' received", a)
	action, ok := a.(*fleetapi.ActionUpgrade)
	if !ok {
		return fmt.Errorf("invalid type, expected ActionUpgrade and received %T", a)
	}

	return h.coord.Upgrade(ctx, action.Version, action.SourceURI, action)
}
