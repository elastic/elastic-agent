// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package handlers

import (
	"context"
	"errors"
	"fmt"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
	"github.com/elastic/elastic-agent/internal/pkg/agent/protection"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi/acker"
	"github.com/elastic/elastic-agent/pkg/core/logger"
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

// Uninstall is a handler for the UNINSTALL action. It verifies the action
// signature and, when it passes, hands off to the coordinator which spawns a
// detached uninstaller. Expiry and grace-period are enforced by the dispatcher
// on receipt, not here: reaching the handler is the point of no return.
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
}

// NewUninstall creates a new Uninstall handler.
func NewUninstall(log *logger.Logger, agentInfo info.Agent, coord uninstallCoordinator) *Uninstall {
	return &Uninstall{
		log:       log,
		agentInfo: agentInfo,
		coord:     coord,
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
	// Verify the action signature (tamper protection). Only the signature is
	// re-checked here; the grace-period window and expiry are enforced by the
	// dispatcher on receipt (an expired or out-of-window action is rejected before
	// it is ever scheduled). Reaching the handler is the point of no return: the
	// host may have hibernated and the action expired while it waited out its
	// grace period, but re-rejecting it here would needlessly leave the agent
	// installed, so once invoked we commit to the uninstall.
	if _, err := protection.VerifyActionSignature(action, h.coord.Protection().SignatureValidationKey, h.agentInfo.AgentID()); err != nil {
		return fmt.Errorf("uninstall action %s rejected: signature verification failed: %w", action.ActionID, err)
	}

	// The dispatcher may have rejected the action on receipt (e.g. its start_time
	// is outside the allowed grace-period window, or it could never run before
	// expiring) by setting action.Err and dispatching it immediately without
	// scheduling. Ack that failure now.
	if action.Err != nil {
		h.log.Warnf("handlerUninstall: action '%s' rejected before scheduling: %v", action.ActionID, action.Err)
		return h.ackNow(ctx, ack, action)
	}

	// The UNINSTALL action is not proxied to Endpoint. A tamper-protected
	// (Elastic Defend) agent is uninstalled by handling the preceding UNENROLL
	// action, which removes Endpoint; by the time this action runs Endpoint is
	// already gone, so there is nothing to notify.

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
