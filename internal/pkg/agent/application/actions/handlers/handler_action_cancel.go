// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package handlers

import (
	"context"
	"fmt"

	"github.com/elastic/elastic-agent/internal/pkg/fleetapi"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi/acker"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

type queueCanceler interface {
	Cancel(id string) int
}

// Cancel is a handler for CANCEL actions.
type Cancel struct {
	log *logger.Logger
	c   queueCanceler
}

// NewCancel creates a new Cancel handler that uses the passed queue canceller.
func NewCancel(log *logger.Logger, cancel queueCanceler) *Cancel {
	return &Cancel{
		log: log,
		c:   cancel,
	}
}

// Handle will cancel any actions in the queue that match target_id.
func (h *Cancel) Handle(ctx context.Context, a fleetapi.Action, acker acker.Acker) error {
	action, ok := a.(*fleetapi.ActionCancel)
	if !ok {
		return fmt.Errorf("invalid type, expected ActionCancel and received %T", a)
	}
	n := h.c.Cancel(action.TargetID)
	if n == 0 {
		h.log.Debugf("Cancel action id: %s target id: %s found no actions in queue.", action.ActionID, action.TargetID)
		return nil
	}
	h.log.Infof("Cancel action id: %s target id: %s removed %d action(s) from queue.", action.ActionID, action.TargetID, n)
	return nil
}
