// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package handlers

import (
	"context"
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
	log       *logger.Logger
	coord     *coordinator.Coordinator
	bkgAction *fleetapi.ActionUpgrade
	m         sync.Mutex
}

// NewUpgrade creates a new Upgrade handler.
func NewUpgrade(log *logger.Logger, coord *coordinator.Coordinator) *Upgrade {
	return &Upgrade{
		log:   log,
		coord: coord,
	}
}

// Handle handles UPGRADE action.
func (h *Upgrade) Handle(ctx context.Context, a fleetapi.Action, ack acker.Acker) error {
	h.log.Debugf("handlerUpgrade: action '%+v' received", a)
	action, ok := a.(*fleetapi.ActionUpgrade)
	if !ok {
		return fmt.Errorf("invalid type, expected ActionUpgrade and received %T", a)
	}
	go func() {
		h.m.Lock()
		if h.bkgAction != nil {
			h.log.Infof("upgrade to version %s already running in background", h.bkgAction.Version)
			h.m.Unlock()
			return
		}
		h.bkgAction = action
		h.m.Unlock()
		h.log.Infof("starting upgrade to version %s in background", action.Version)
		if err := h.coord.Upgrade(ctx, action.Version, action.SourceURI, action, false); err != nil {
			h.log.Errorf("upgrade to version %s failed: %v", action.Version, err)
			if err := ack.Ack(ctx, action); err != nil {
				h.log.Errorf("ack of failed upgrade failed: %v", err)
			}
			if err := ack.Commit(ctx); err != nil {
				h.log.Errorf("commit of ack for failed upgrade failed: %v", err)
			}
		}
		h.m.Lock()
		h.bkgAction = nil
		h.m.Unlock()
	}()
	return nil
}
