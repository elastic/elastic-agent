// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package handlers

import (
	"context"
	"fmt"
	"time"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/coordinator"
	"github.com/elastic/elastic-agent/internal/pkg/config"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi/acker"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

const (
	unenrollTimeout = 15 * time.Second
)

type stateStore interface {
	Add(fleetapi.Action)
	AckToken() string
	SetAckToken(ackToken string)
	Save() error
	Actions() []fleetapi.Action
}

// Unenroll results in  running agent entering idle state, non managed non standalone.
// For it to be operational again it needs to be either enrolled or reconfigured.
type Unenroll struct {
	log        *logger.Logger
	ch         chan coordinator.ConfigChange
	closers    []context.CancelFunc
	stateStore stateStore
}

// NewUnenroll creates a new Unenroll handler.
func NewUnenroll(
	log *logger.Logger,
	ch chan coordinator.ConfigChange,
	closers []context.CancelFunc,
	stateStore stateStore,
) *Unenroll {
	return &Unenroll{
		log:        log,
		ch:         ch,
		closers:    closers,
		stateStore: stateStore,
	}
}

// Handle handles UNENROLL action.
func (h *Unenroll) Handle(ctx context.Context, a fleetapi.Action, acker acker.Acker) error {
	h.log.Debugf("handlerUnenroll: action '%+v' received", a)
	action, ok := a.(*fleetapi.ActionUnenroll)
	if !ok {
		return fmt.Errorf("invalid type, expected ActionUnenroll and received %T", a)
	}

	if action.IsDetected {
		// not from Fleet; so we set it to nil so policyChange doesn't ack it
		a = nil
	}

	unenrollPolicy := newPolicyChange(ctx, config.New(), a, acker, true)
	h.ch <- unenrollPolicy

	if h.stateStore != nil {
		// backup action for future start to avoid starting fleet gateway loop
		h.stateStore.Add(a)
		if err := h.stateStore.Save(); err != nil {
			h.log.Warnf("Failed to update state store: %v", err)
		}
	}

	unenrollCtx, cancel := context.WithTimeout(ctx, unenrollTimeout)
	defer cancel()

	unenrollPolicy.WaitAck(unenrollCtx)

	// close fleet gateway loop
	for _, c := range h.closers {
		c()
	}

	return nil
}
