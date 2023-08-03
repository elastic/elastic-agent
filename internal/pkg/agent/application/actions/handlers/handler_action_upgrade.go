// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package handlers

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/elastic/elastic-agent/internal/pkg/fleetapi"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi/acker"
	"github.com/elastic/elastic-agent/pkg/core/logger"
	"github.com/elastic/elastic-agent/pkg/features"
)

// Upgrade is a handler for UPGRADE action.
// After running Upgrade agent should download its own version specified by action
// from repository specified by fleet.
type Upgrade struct {
	log        *logger.Logger
	coord      upgradeCoordinator
	bkgActions []fleetapi.Action
	bkgCancel  context.CancelFunc
	bkgMutex   sync.Mutex

	tamperProtectionFn func() bool // allows to inject the flag for tests, defaults to features.TamperProtection
}

// NewUpgrade creates a new Upgrade handler.
func NewUpgrade(log *logger.Logger, coord upgradeCoordinator) *Upgrade {
	return &Upgrade{
		log:                log,
		coord:              coord,
		tamperProtectionFn: features.TamperProtection,
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

	asyncCtx, runAsync := h.getAsyncContext(ctx, a, ack)
	if !runAsync {
		return nil
	}

	if h.tamperProtectionFn() {
		// Find inputs that want to receive UPGRADE action
		// Endpoint needs to receive a signed UPGRADE action in order to be able to uncontain itself
		state := h.coord.State()
		ucs := findMatchingUnitsByActionType(state, a.Type())
		if len(ucs) > 0 {
			h.log.Debugf("handlerUpgrade: proxy/dispatch action '%+v'", a)
			err := notifyUnitsOfProxiedAction(ctx, h.log, action, ucs, h.coord.PerformAction)
			h.log.Debugf("handlerUpgrade: after action dispatched '%+v', err: %v", a, err)
			if err != nil {
				return err
			}
		} else {
			// Log and continue
			h.log.Debugf("No components running for %v action type", a.Type())
		}
	}

	go func() {
		h.log.Infof("starting upgrade to version %s in background", action.Version)
		if err := h.coord.Upgrade(asyncCtx, action.Version, action.SourceURI, action, false, false); err != nil {
			h.log.Errorf("upgrade to version %s failed: %v", action.Version, err)
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

// ackActions Acks all the actions in bkgActions, and deletes entries from bkgActions.
// User is responsible for obtaining and releasing bkgMutex lock
func (h *Upgrade) ackActions(ctx context.Context, ack acker.Acker) {
	for _, a := range h.bkgActions {
		if err := ack.Ack(ctx, a); err != nil {
			h.log.Errorf("ack of failed upgrade failed: %v", err)
		}
	}
	h.bkgActions = nil
	if err := ack.Commit(ctx); err != nil {
		h.log.Errorf("commit of ack for failed upgrade failed: %v", err)
	}
}

// getAsyncContext returns a cancelContext and whether or not to run the upgrade
func (h *Upgrade) getAsyncContext(ctx context.Context, action fleetapi.Action, ack acker.Acker) (context.Context, bool) {
	h.bkgMutex.Lock()
	defer h.bkgMutex.Unlock()
	// If no existing actions, run this one
	if len(h.bkgActions) == 0 {
		h.bkgActions = append(h.bkgActions, action)
		c, cancel := context.WithCancel(ctx)
		h.bkgCancel = cancel
		return c, true
	}
	// If upgrade to same version, save action to ack when first upgrade completes
	upgradeAction, ok := action.(*fleetapi.ActionUpgrade)
	if !ok {
		h.log.Errorf("invalid type, expected ActionUpgrade and received %T", action)
		return nil, false
	}
	// only need to check first action since all actions must be upgrades to same version
	bkgAction, ok := h.bkgActions[0].(*fleetapi.ActionUpgrade)
	if !ok {
		h.log.Errorf("invalid type, expected ActionUpgrade and received %T", action)
		return nil, false
	}
	if (upgradeAction.Version == bkgAction.Version) && (upgradeAction.SourceURI == bkgAction.SourceURI) {
		h.log.Infof("Duplicate upgrade to version %s received", bkgAction.Version)
		h.bkgActions = append(h.bkgActions, action)
		return nil, false
	}

	// Versions must be different, cancel the first upgrade and run the new one
	h.log.Infof("Canceling upgrade to version %s received", bkgAction.Version)
	h.bkgCancel()

	// Ack here because we have the lock, and we need to clear out the saved actions
	h.ackActions(ctx, ack)

	h.bkgActions = append(h.bkgActions, action)
	c, cancel := context.WithCancel(ctx)
	h.bkgCancel = cancel
	return c, true
}
