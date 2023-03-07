// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package handlers

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/coordinator"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi/acker"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

// Upgrade is a handler for UPGRADE action.
// After running Upgrade agent should download its own version specified by action
// from repository specified by fleet.
type Upgrade struct {
	log          *logger.Logger
	coord        *coordinator.Coordinator
	actions      []fleetapi.Action
	actionsMutex sync.Mutex
}

// NewUpgrade creates a new Upgrade handler.
func NewUpgrade(log *logger.Logger, coord *coordinator.Coordinator) *Upgrade {
	return &Upgrade{
		log:   log,
		coord: coord,
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
	go func() {
		h.log.Infof("starting upgrade to version %s in background", action.Version)
		h.addAction(a)
		if err := h.coord.Upgrade(ctx, action.Version, action.SourceURI, action, false); err != nil {
			if errors.Is(err, coordinator.ErrUpgradeInProgress) {
				return
			}

			h.log.Errorf("upgrade to version %s failed: %v", action.Version, err)
			h.ackActions(ctx, ack)
		}
	}()
	return nil
}

func (h *Upgrade) addAction(action fleetapi.Action) {
	h.actionsMutex.Lock()
	defer h.actionsMutex.Unlock()
	h.actions = append(h.actions, action)
}

func (h *Upgrade) ackActions(ctx context.Context, ack acker.Acker) {
	h.actionsMutex.Lock()
	defer h.actionsMutex.Unlock()
	for _, a := range h.actions {
		if err := ack.Ack(ctx, a); err != nil {
			h.log.Errorf("ack of failed upgrade failed: %v", err)
		}
	}
	h.actions = nil
	if err := ack.Commit(ctx); err != nil {
		h.log.Errorf("commit of ack for failed upgrade failed: %v", err)
	}
}
