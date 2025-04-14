// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package handlers

import (
	"context"
	"fmt"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi/acker"
	"github.com/elastic/elastic-agent/pkg/core/logger"
	"github.com/elastic/elastic-agent/pkg/features"
)

type MigrateCoordinator interface {
	Migrate(_ context.Context, _ *fleetapi.ActionMigrate) error
}

// Settings handles settings change coming from fleet and updates log level.
type Migrate struct {
	log       *logger.Logger
	agentInfo info.Agent
	coord     MigrateCoordinator

	tamperProtectionFn func() bool // allows to inject the flag for tests, defaults to features.TamperProtection
}

// NewSettings creates a new Settings handler.
func NewMigrate(
	log *logger.Logger,
	agentInfo info.Agent,
	coord MigrateCoordinator,
) *Migrate {
	return &Migrate{
		log:                log,
		agentInfo:          agentInfo,
		coord:              coord,
		tamperProtectionFn: features.TamperProtection,
	}
}

// Handle handles MIGRATE action.
func (h *Migrate) Handle(ctx context.Context, a fleetapi.Action, ack acker.Acker) error {
	h.log.Debugf("handlerMigrate: action '%+v' received", a)

	action, ok := a.(*fleetapi.ActionMigrate)
	if !ok {
		return fmt.Errorf("invalid type, expected ActionSettings and received %T", a)
	}

	if h.tamperProtectionFn() {
		// tamper protected agents are unsupported, fail fast
		err := errors.New("unsupported action: tamper protected agent")
		action.Err = err

		if err := ack.Ack(ctx, action); err != nil {
			h.log.Errorw("failed to ack migrate action",
				"error.message", err,
				"action", action)
		}

		if err := ack.Commit(ctx); err != nil {
			h.log.Errorw("failed to commit migrate action",
				"error.message", err,
				"action", action)
		}
		return err
	}

	if err := h.coord.Migrate(ctx, action); err != nil {
		return fmt.Errorf("migration of agent to a new cluster failed: %w", err)
	}

	return nil
}
