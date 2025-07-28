// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package handlers

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/coordinator"
	fleetgateway "github.com/elastic/elastic-agent/internal/pkg/agent/application/gateway/fleet"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/reexec"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/internal/pkg/agent/protection"
	"github.com/elastic/elastic-agent/internal/pkg/core/backoff"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi/acker"
	"github.com/elastic/elastic-agent/pkg/core/logger"
	"github.com/elastic/elastic-agent/pkg/features"
)

const ()

type migrateCoordinator interface {
	Migrate(_ context.Context, _ *fleetapi.ActionMigrate, _ func(done <-chan struct{}) backoff.Backoff) error
	ReExec(callback reexec.ShutdownCallbackFn, argOverrides ...string)
	HasEndpoint() bool
	Protection() protection.Config
}

// Migrate handles migrate change coming from fleet.
type Migrate struct {
	log       *logger.Logger
	agentInfo info.Agent
	coord     migrateCoordinator

	tamperProtectionFn func() bool // allows to inject the flag for tests, defaults to features.TamperProtection
}

// NewMigrate creates a new Migrate handler.
func NewMigrate(
	log *logger.Logger,
	agentInfo info.Agent,
	coord migrateCoordinator,
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
		return fmt.Errorf("invalid type, expected ActionMigrate and received %T", a)
	}

	// if endpoint is present do not proceed
	if h.tamperProtectionFn() && h.coord.HasEndpoint() {
		err := errors.New("unsupported action: tamper protected agent")
		h.ackFailure(ctx, err, action, ack)
		return err
	}

	signatureValidationKey := h.coord.Protection().SignatureValidationKey
	signedData, err := protection.ValidateAction(action, signatureValidationKey, h.agentInfo.AgentID())
	if len(signatureValidationKey) != 0 && errors.Is(err, protection.ErrNotSigned) {
		return err
	} else if err != nil && !errors.Is(err, protection.ErrNotSigned) {
		return err
	}

	if signedData != nil {
		if err := json.Unmarshal(signedData, &action.Data); err != nil {
			return fmt.Errorf("failed to convert signed data to action data: %w", err)
		}
	}

	if err := h.coord.Migrate(ctx, action, fleetgateway.RequestBackoff); err != nil {
		// this should not happen, unmanaged agent should not receive the action
		// defensive coding to avoid misbehavior
		if errors.Is(err, coordinator.ErrNotManaged) {
			return errors.New("unmanaged agent, use Enroll instead")
		}

		// ack failure
		h.ackFailure(ctx, err, action, ack)

		if errors.Is(err, coordinator.ErrFleetServer) {
			return errors.New("action not available for agents running Fleet Server")
		}

		return fmt.Errorf("migration of agent to a new cluster failed: %w", err)
	}

	// reexec and load new config
	h.coord.ReExec(nil)
	return nil
}

func (h *Migrate) ackFailure(ctx context.Context, err error, action *fleetapi.ActionMigrate, acker acker.Acker) {
	action.Err = err

	if err := acker.Ack(ctx, action); err != nil {
		h.log.Errorw("failed to ack migrate action",
			"error.message", err,
			"action", action)
	}

	if err := acker.Commit(ctx); err != nil {
		h.log.Errorw("failed to commit migrate action",
			"error.message", err,
			"action", action)
	}
}
