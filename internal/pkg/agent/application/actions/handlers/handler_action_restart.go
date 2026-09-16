// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package handlers

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/elastic/elastic-agent/internal/pkg/fleetapi/acker"
	"github.com/elastic/elastic-agent/pkg/core/logger"
	"github.com/elastic/elastic-agent/pkg/features"
	"github.com/elastic/elastic-agent/pkg/fleetapi"
)

// restartCoordinator is the subset of the coordinator used by the Restart handler.
type restartCoordinator interface {
	actionCoordinator
	// Restart re-executes the agent. The action is acknowledged on the next
	// startup, not here.
	Restart(ctx context.Context, action *fleetapi.ActionRestart) error
}

// restartStateStore is the subset of the state store used by the Restart handler.
type restartStateStore interface {
	SetPendingAckAction(fleetapi.Action)
	ClearPendingAckAction()
	Save() error
}

// Restart is a handler for the RESTART action. It persists the action, re-execs
// the agent (reusing the upgrade restart machinery) and does NOT acknowledge the
// action here. The acknowledgement happens on the next startup, once the restart
// has actually completed.
type Restart struct {
	log        *logger.Logger
	coord      restartCoordinator
	stateStore restartStateStore

	tamperProtectionFn func() bool // allows to inject the flag for tests, defaults to features.TamperProtection
	nowFn              func() time.Time
}

// NewRestart creates a new Restart handler.
func NewRestart(log *logger.Logger, coord restartCoordinator, stateStore restartStateStore) *Restart {
	return &Restart{
		log:                log,
		coord:              coord,
		stateStore:         stateStore,
		tamperProtectionFn: features.TamperProtection,
		nowFn:              time.Now,
	}
}

// Handle handles the RESTART action.
func (h *Restart) Handle(ctx context.Context, a fleetapi.Action, ack acker.Acker) error {
	h.log.Debugf("handlerRestart: action '%+v' received", a)
	action, ok := a.(*fleetapi.ActionRestart)
	if !ok {
		return fmt.Errorf("invalid type, expected ActionRestart and received %T", a)
	}

	// Do not restart if the action is expired or carries an invalid expiration.
	// In both cases we ack the error so Fleet learns about the failure instead
	// of silently restarting.
	exp, err := action.Expiration()
	switch {
	case err == nil:
		if h.nowFn().After(exp) {
			h.log.Warnf("handlerRestart: action '%s' expired at %s, skipping restart", action.ActionID, exp)
			action.Err = fmt.Errorf("restart action expired at %s", exp)
			return h.ackNow(ctx, ack, action)
		}
	case errors.Is(err, fleetapi.ErrNoExpiration):
		// No expiration set; the action never expires, proceed with the restart.
	default:
		// Malformed expiration timestamp; treat the action as invalid.
		h.log.Warnf("handlerRestart: action '%s' has an invalid expiration, skipping restart: %v", action.ActionID, err)
		action.Err = fmt.Errorf("restart action has an invalid expiration: %w", err)
		return h.ackNow(ctx, ack, action)
	}

	// Under tamper protection, Endpoint needs to receive the signed RESTART
	// action so it can react to the imminent restart. Mirrors the UPGRADE flow.
	if h.tamperProtectionFn() {
		state := h.coord.State()
		ucs := findMatchingUnitsByActionType(state, a.Type())
		if len(ucs) > 0 {
			if err := notifyUnitsOfProxiedAction(ctx, h.log, action, ucs, h.coord.PerformAction); err != nil {
				return err
			}
		} else {
			h.log.Debugf("No components running for %v action type", a.Type())
		}
	}

	// Persist the action before restarting so it can be acknowledged on the
	// next startup.
	h.stateStore.SetPendingAckAction(action)
	if err := h.stateStore.Save(); err != nil {
		return fmt.Errorf("failed to persist restart action to state store: %w", err)
	}

	if err := h.coord.Restart(ctx, action); err != nil {
		// The restart did not happen, so there will be no startup ack. Clear the
		// persisted action and ack the failure now so Fleet learns about it.
		h.stateStore.ClearPendingAckAction()
		if serr := h.stateStore.Save(); serr != nil {
			h.log.Warnf("failed to clear restart action from state store: %v", serr)
		}
		action.Err = err
		if aerr := h.ackNow(ctx, ack, action); aerr != nil {
			return errors.Join(err, aerr)
		}
		return err
	}

	return nil
}

// ackNow acknowledges the action and commits immediately.
func (h *Restart) ackNow(ctx context.Context, ack acker.Acker, action *fleetapi.ActionRestart) error {
	if err := ack.Ack(ctx, action); err != nil {
		return fmt.Errorf("failed to ack restart action: %w", err)
	}
	if err := ack.Commit(ctx); err != nil {
		return fmt.Errorf("failed to commit restart action ack: %w", err)
	}
	return nil
}
