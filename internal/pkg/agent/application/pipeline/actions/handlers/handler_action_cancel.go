package handlers

import (
	"context"
	"fmt"

	"github.com/elastic/elastic-agent/internal/pkg/agent/storage/store"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

type queueCanceler interface {
	Cancel(id string) int
}

type Cancel struct {
	log *logger.Logger
	c   queueCanceler
}

func NewCancel(log *logger.Logger, cancel queueCanceler) *Cancel {
	return &Cancel{
		log: log,
		c:   cancel,
	}
}

func (h *Cancel) Handle(ctx context.Context, a fleetapi.Action, acker store.FleetAcker) error {
	action, ok := a.(*fleetapi.ActionCancel)
	if !ok {
		return fmt.Errorf("invalid type, expected ActionCancel and received %T", a)
	}
	n := h.c.Cancel(action.TargetID)
	if n == 0 {
		h.log.Debug("Cancel action id: %s target id: %s found no actions in queue.", action.ActionID, action.TargetID)
		return nil
	}
	h.log.Info("Cancel action id: %s target id: %s removed %d action(s) from queue.", action.ActionID, action.TargetID, n)
	// TODO ack action.TargetID as failed
	return nil
}
