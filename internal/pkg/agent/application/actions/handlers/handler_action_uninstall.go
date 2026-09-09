// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package handlers

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
	"github.com/elastic/elastic-agent/internal/pkg/agent/protection"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi/acker"
	"github.com/elastic/elastic-agent/pkg/core/logger"
	"github.com/elastic/elastic-agent/pkg/features"
	"github.com/elastic/elastic-agent/pkg/fleetapi"
)

// uninstallCoordinator is the subset of the coordinator used by the Uninstall handler.
type uninstallCoordinator interface {
	actionCoordinator
	// Uninstall spawns a detached process that uninstalls the agent. The action
	// is acknowledged by that process, not here.
	Uninstall(ctx context.Context, action *fleetapi.ActionUninstall) error
	// Protection returns the agent's tamper-protection configuration, including
	// the key used to verify signed actions.
	Protection() protection.Config
}

// Uninstall is a handler for the UNINSTALL action. It performs the checks that
// can still be recovered from (expiry, capability, tamper protection) and, when
// they pass, hands off to the coordinator which spawns a detached uninstaller.
//
// The success path is NOT acknowledged here: the uninstall is terminal, so the
// detached uninstaller acknowledges the action to Fleet at the point of no
// return. Only failures that happen before the agent is handed off (invalid
// action, or the coordinator refusing/failing to spawn the uninstaller) are
// acknowledged here, so Fleet learns the uninstall did not start.
type Uninstall struct {
	log       *logger.Logger
	agentInfo info.Agent
	coord     uninstallCoordinator

	tamperProtectionFn func() bool // allows to inject the flag for tests, defaults to features.TamperProtection
	nowFn              func() time.Time
}

// NewUninstall creates a new Uninstall handler.
func NewUninstall(log *logger.Logger, agentInfo info.Agent, coord uninstallCoordinator) *Uninstall {
	return &Uninstall{
		log:                log,
		agentInfo:          agentInfo,
		coord:              coord,
		tamperProtectionFn: features.TamperProtection,
		nowFn:              time.Now,
	}
}

// Handle handles the UNINSTALL action.
func (h *Uninstall) Handle(ctx context.Context, a fleetapi.Action, ack acker.Acker) error {
	h.log.Debugf("handlerUninstall: action '%+v' received", a)
	action, ok := a.(*fleetapi.ActionUninstall)
	if !ok {
		return fmt.Errorf("invalid type, expected ActionUninstall and received %T", a)
	}

	// Verify the action signature before doing anything destructive. When a
	// signature validation key is configured (tamper protection), the action must
	// be signed and valid; a missing or invalid signature rejects the action so it
	// is not executed. The dispatcher performs the same check on receipt (so an
	// invalid action is never scheduled); this is the defensive check at execution
	// time, also covering actions restored from the persisted queue on restart.
	// The error is returned (not acked) so a potentially tampered action is not
	// acknowledged, mirroring the MIGRATE handler.
	if _, err := protection.VerifyActionSignature(action, h.coord.Protection().SignatureValidationKey, h.agentInfo.AgentID()); err != nil {
		return fmt.Errorf("uninstall action %s rejected: signature verification failed: %w", action.ActionID, err)
	}

	// The dispatcher may have rejected the action on receipt (e.g. its grace
	// period would end at or after the action expiration) by setting action.Err
	// and dispatching it immediately without scheduling. Ack that failure now.
	if action.Err != nil {
		h.log.Warnf("handlerUninstall: action '%s' rejected before scheduling: %v", action.ActionID, action.Err)
		return h.ackNow(ctx, ack, action)
	}

	// Do not uninstall if the action is expired or carries an invalid
	// expiration. In both cases we ack the error so Fleet learns about the
	// failure instead of silently uninstalling.
	exp, err := action.Expiration()
	switch {
	case err == nil:
		if h.nowFn().After(exp) {
			h.log.Warnf("handlerUninstall: action '%s' expired at %s, skipping uninstall", action.ActionID, exp)
			action.Err = fmt.Errorf("uninstall action expired at %s", exp)
			return h.ackNow(ctx, ack, action)
		}
	case errors.Is(err, fleetapi.ErrNoExpiration):
		// No expiration set; the action never expires, proceed with the uninstall.
	default:
		// Malformed expiration timestamp; treat the action as invalid.
		h.log.Warnf("handlerUninstall: action '%s' has an invalid expiration, skipping uninstall: %v", action.ActionID, err)
		action.Err = fmt.Errorf("uninstall action has an invalid expiration: %w", err)
		return h.ackNow(ctx, ack, action)
	}

	// Under tamper protection, Endpoint needs to receive the signed UNINSTALL
	// action so it can uncontain itself before the agent is removed. Mirrors the
	// UNENROLL flow.
	if h.tamperProtectionFn() {
		state := h.coord.State()
		ucs := findMatchingUnitsByActionType(state, a.Type())
		if len(ucs) > 0 {
			if err := notifyUnitsOfProxiedAction(ctx, h.log, action, ucs, h.coord.PerformAction); err != nil {
				// The uninstaller is not started, so it will not acknowledge the
				// action. Ack the failure now so Fleet does not keep redelivering an
				// action that will never uninstall; the agent stays installed.
				action.Err = err
				if aerr := h.ackNow(ctx, ack, action); aerr != nil {
					return errors.Join(err, aerr)
				}
				return err
			}
		} else {
			h.log.Debugf("No components running for %v action type", a.Type())
		}
	}

	if err := h.coord.Uninstall(ctx, action); err != nil {
		// The uninstaller never started, so it will not acknowledge the action.
		// Ack the failure now so Fleet learns the uninstall did not happen; the
		// agent remains installed and functional.
		action.Err = err
		if aerr := h.ackNow(ctx, ack, action); aerr != nil {
			return errors.Join(err, aerr)
		}
		return err
	}

	// Success: the detached uninstaller owns the acknowledgement. Do not ack here.
	return nil
}

// ackNow acknowledges the action and commits immediately.
func (h *Uninstall) ackNow(ctx context.Context, ack acker.Acker, action *fleetapi.ActionUninstall) error {
	if err := ack.Ack(ctx, action); err != nil {
		return fmt.Errorf("failed to ack uninstall action: %w", err)
	}
	if err := ack.Commit(ctx); err != nil {
		return fmt.Errorf("failed to commit uninstall action ack: %w", err)
	}
	return nil
}
