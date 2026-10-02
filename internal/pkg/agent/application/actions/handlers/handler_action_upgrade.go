// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package handlers

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/coordinator"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi/acker"
	"github.com/elastic/elastic-agent/pkg/core/logger"
	"github.com/elastic/elastic-agent/pkg/features"
	"github.com/elastic/elastic-agent/pkg/fleetapi"
)

// Upgrade is a handler for UPGRADE action.
// After running Upgrade agent should download its own version specified by action
// from repository specified by fleet.
type Upgrade struct {
	log        *logger.Logger
	coord      upgradeCoordinator
	bkgActions []*fleetapi.ActionUpgrade
	bkgCancel  context.CancelFunc
	bkgMutex   sync.Mutex

	tamperProtectionFn           func() bool                                                                                                                            // allows to inject the flag for tests, defaults to features.TamperProtection
	notifyUnitsOfProxiedActionFn func(ctx context.Context, log *logp.Logger, action dispatchableAction, ucs []unitWithComponent, performAction performActionFunc) error // allows to inject the function for tests, defaults to notifyUnitsOfProxiedAction
	endpointWaitTimeout          time.Duration                                                                                                                          // how long to wait for endpoint to appear in coordinator state; overrideable in tests
	endpointPollInterval         time.Duration                                                                                                                          // how often to poll coordinator state while waiting; overrideable in tests
}

// NewUpgrade creates a new Upgrade handler.
func NewUpgrade(log *logger.Logger, coord upgradeCoordinator) *Upgrade {
	return &Upgrade{
		log:                          log,
		coord:                        coord,
		tamperProtectionFn:           features.TamperProtection,
		notifyUnitsOfProxiedActionFn: notifyUnitsOfProxiedAction,
		endpointWaitTimeout:          2 * time.Minute,
		endpointPollInterval:         2 * time.Second,
	}
}

// Handle handles UPGRADE action.  Returns immediately and the actual
// upgrade happens asynchronously.  This allows for downloads to
// happen without blocking updates.  If multiple upgrades are sent
// then we ack them all if there is an error, but only the first actually executes.
// If successful, reboot does ACK and check-in.
func (h *Upgrade) Handle(ctx context.Context, a fleetapi.Action, ack acker.Acker) error {
	h.log.Debugf("handlerUpgrade: action '%+v' received", a)
	action, ok := a.(*fleetapi.ActionUpgrade)
	if !ok {
		return fmt.Errorf("invalid type, expected ActionUpgrade and received %T", a)
	}

	asyncCtx, runAsync := h.getAsyncContext(ctx, action, ack)
	if !runAsync {
		return nil
	}

	uOpts := []coordinator.UpgradeOpt{
		coordinator.WithRollback(action.Data.Rollback),
	}
	if h.tamperProtectionFn() {
		// Deferred to the pre-upgrade callback so component discovery runs after
		// the policy is guaranteed to have been applied.
		uOpts = append(uOpts, coordinator.WithPreUpgradeCallback(func(ctx context.Context, log *logger.Logger, action *fleetapi.ActionUpgrade) error {
			return h.notifyEndpointOfUpgrade(ctx, log, action)
		}))
	}

	go func() {
		h.log.Infof("starting upgrade to version %s in background", action.Data.Version)
		if err := h.coord.Upgrade(asyncCtx, action.Data.Version, action.Data.Sources, action, uOpts...); err != nil {
			h.log.Errorf("upgrade to version %s failed: %v", action.Data.Version, err)
			// If context is cancelled in getAsyncContext, the actions are acked there
			if !errors.Is(asyncCtx.Err(), context.Canceled) {
				h.bkgMutex.Lock()
				h.ackActions(asyncCtx, ack)
				h.bkgMutex.Unlock()
			}
		}
	}()
	return nil
}

// notifyEndpointOfUpgrade waits for a component that handles the given action type
// to appear in coordinator state, then dispatches the action so the component can
// lift tamper protection before the installer runs. If no such component is found
// within endpointWaitTimeout the upgrade proceeds without notification.
func (h *Upgrade) notifyEndpointOfUpgrade(ctx context.Context, log *logger.Logger, action *fleetapi.ActionUpgrade) error {
	timeoutCtx, cancel := context.WithTimeout(ctx, h.endpointWaitTimeout)
	defer cancel()

	ticker := time.NewTicker(h.endpointPollInterval)
	defer ticker.Stop()

	for {
		state := h.coord.State()

		if state.PolicyApplied {
			expected := expectedComponentsForActionType(state, action.Type())
			if len(expected) == 0 {
				// Policy is applied and no component handles this action type.
				log.Debugf("handlerUpgrade: no component configured for %v action type; skipping tamper-protection notification", action.Type())
				return nil
			}
			ucs := findMatchingUnitsByActionType(state, action.Type())
			if allComponentsReady(ucs, expected) {
				log.Debugf("handlerUpgrade: dispatching %v action to %d component(s)", action.Type(), len(expected))
				if err := h.notifyUnitsOfProxiedActionFn(timeoutCtx, log, action, ucs, h.coord.PerformAction); err != nil {
					return fmt.Errorf("failed to notify components of upgrade action: %w", err)
				}
				return nil
			}
			// Some expected components not yet ready — wait.
		}

		select {
		case <-timeoutCtx.Done():
			if ctx.Err() != nil {
				// Parent context cancelled — propagate so the coordinator can abort.
				return ctx.Err()
			}
			// Our wait budget expired; proceed and let the installer surface the failure.
			logUpgradeNotifyTimeout(log, state, action.Type())
			return nil
		case <-ticker.C:
		}
	}
}

// ackActions Acks all the actions in bkgActions, and deletes entries from bkgActions.
// User is responsible for obtaining and releasing bkgMutex lock
func (h *Upgrade) ackActions(ctx context.Context, ack acker.Acker) {
	for _, a := range h.bkgActions {
		h.ackAction(ctx, ack, a, false)
	}
	h.bkgActions = nil
	if err := ack.Commit(ctx); err != nil {
		h.log.Errorf("commit of ack for failed upgrade failed: %v", err)
	}
}

// ackActions Acks all the actions in bkgActions, and deletes entries from bkgActions.
// User is responsible for obtaining and releasing bkgMutex lock
func (h *Upgrade) ackAction(ctx context.Context, ack acker.Acker, action fleetapi.Action, commit bool) {
	if err := ack.Ack(ctx, action); err != nil {
		h.log.Errorf("ack of failed upgrade failed: %v", err)
	}

	if commit {
		if err := ack.Commit(ctx); err != nil {
			h.log.Errorf("commit of ack for failed upgrade failed: %v", err)
		}
	}
}

// getAsyncContext returns a cancelContext and whether or not to run the upgrade
func (h *Upgrade) getAsyncContext(ctx context.Context, upgradeAction *fleetapi.ActionUpgrade, ack acker.Acker) (context.Context, bool) {
	h.bkgMutex.Lock()
	defer h.bkgMutex.Unlock()

	// Log current upgrade actions queue for debugging
	h.log.Debugf("Current upgrade actions queue: %d actions", len(h.bkgActions))
	for i, bkgAction := range h.bkgActions {
		h.log.Debugf("Queue[%d]: ActionID=%s, Version=%s", i, bkgAction.ActionID, bkgAction.Data.Version)
	}

	// If no existing actions, run this one
	if len(h.bkgActions) == 0 {
		h.bkgActions = append(h.bkgActions, upgradeAction)
		c, cancel := context.WithCancel(ctx)
		h.bkgCancel = cancel
		return c, true
	}
	// If upgrade to same version, save action to ack when first upgrade completes
	// only need to check first action since all actions must be upgrades to same version
	bkgAction := h.bkgActions[0]
	if upgradeAction.ActionID == bkgAction.ActionID {
		h.log.Infof("Duplicate upgrade to version %s received",
			bkgAction.Data.Version)
		return nil, false
	}

	if upgradeAction.Data.Version == bkgAction.Data.Version &&
		slices.Equal(upgradeAction.Data.Sources, bkgAction.Data.Sources) {
		// not the same action this one needs to be acked
		h.log.Infof("Duplicate upgrade request to same version %s and sources %v, acknowledging new action (ActionID: %s) while keeping existing upgrade running (ActionID: %s)",
			upgradeAction.Data.Version, upgradeAction.Data.Sources, upgradeAction.ActionID, bkgAction.ActionID)

		go func() {
			// kick it off and don't block, lock to prevent race with ackActions from finished upgrade
			h.bkgMutex.Lock()
			defer h.bkgMutex.Unlock()

			h.ackAction(ctx, ack, upgradeAction, true)
		}()
		return nil, false
	}

	// Versions must be different, cancel the first upgrade and run the new one
	h.log.Infof("Canceling upgrade to version %s and starting upgrade to version %s",
		bkgAction.Data.Version, upgradeAction.Data.Version)
	h.bkgCancel()

	// Ack here because we have the lock, and we need to clear out the saved actions
	h.ackActions(ctx, ack)

	h.bkgActions = append(h.bkgActions, upgradeAction)
	c, cancel := context.WithCancel(ctx)
	h.bkgCancel = cancel
	return c, true
}
