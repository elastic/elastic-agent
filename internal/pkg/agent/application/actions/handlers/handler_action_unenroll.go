// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package handlers

import (
	"context"
	"fmt"
	"time"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/coordinator"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/coordinator/state"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/internal/pkg/config"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi/acker"
	"github.com/elastic/elastic-agent/pkg/component"
	"github.com/elastic/elastic-agent/pkg/core/logger"

	"golang.org/x/sync/errgroup"
)

// Interface for coordinator for unenroll handler testability
type ActionCoordinator interface {
	State() state.State
	PerformAction(ctx context.Context, comp component.Component, unit component.Unit, name string, params map[string]interface{}) (map[string]interface{}, error)
}

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
	coord      ActionCoordinator
	ch         chan coordinator.ConfigChange
	closers    []context.CancelFunc
	stateStore stateStore
}

// NewUnenroll creates a new Unenroll handler.
func NewUnenroll(
	log *logger.Logger,
	coord ActionCoordinator,
	ch chan coordinator.ConfigChange,
	closers []context.CancelFunc,
	stateStore stateStore,
) *Unenroll {
	return &Unenroll{
		log:        log,
		coord:      coord,
		ch:         ch,
		closers:    closers,
		stateStore: stateStore,
	}
}

type performActionFunc func(context.Context, component.Component, component.Unit, string, map[string]interface{}) (map[string]interface{}, error)

func dispatchUnenrollInParallel(ctx context.Context, log *logp.Logger, action *fleetapi.ActionUnenroll, comps []component.Component, units []component.Unit, performAction performActionFunc) error {
	if action == nil {
		return nil
	}

	// Deserialize the action into map[string]interface{} for dispatching over to the apps
	params, err := action.MarshalMap()
	if err != nil {
		return err
	}

	g, ctx := errgroup.WithContext(ctx)

	// Iterate through found components and forward the UNENROLL action
	for i := 0; i < len(comps); i++ {
		g.Go(func(idx int) func() error {
			comp := comps[i]
			unit := units[i]
			return func() error {
				log.Debugf("Dispatch %v action to %v", action.Type(), unit.Config.Type)
				res, err := performAction(ctx, comp, unit, unit.Config.Type, params)
				// If Endpoint UNENROLL fails, continue with Agent UNENROLL
				if err != nil {
					// Log and continue
					log.Warnf("UNENROLL failed to dispatch to %v, err: %v", comp.ID, err)
					return err
				} else {
					strErr := readMapString(res, "error", "")
					if strErr != "" {
						log.Warnf("UNENROLL failed for %v, err: %v", comp.ID, strErr)
						return errors.New(strErr)
					}
				}
				return nil
			}
		}(i))
	}

	return g.Wait()
}

// Handle handles UNENROLL action.
func (h *Unenroll) Handle(ctx context.Context, a fleetapi.Action, acker acker.Acker) error {
	h.log.Debugf("handlerUnenroll: action '%+v' received", a)
	action, ok := a.(*fleetapi.ActionUnenroll)
	if !ok {
		return fmt.Errorf("invalid type, expected ActionUnenroll and received %T", a)
	}

	// Find inputs that want to receive UNENROLL action
	// Endpoint needs to receive a signed UNENROLL action in order to be able to uncontain itself
	state := h.coord.State()
	comps, units := findMatchingUnitsByActionType(state, a.Type())
	if len(comps) > 0 {
		err := dispatchUnenrollInParallel(ctx, h.log, action, comps, units, h.coord.PerformAction)
		if err != nil {
			return err
		}
	} else {
		// Log and continue
		h.log.Debugf("No components running for %v action type", a.Type())
	}

	if action.IsDetected {
		// not from Fleet; so we set it to nil so policyChange doesn't ack it
		a = nil
	}

	// Generate empty policy change, this removing all the running components
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

func findMatchingUnitsByActionType(state state.State, typ string) ([]component.Component, []component.Unit) {
	comps := make([]component.Component, 0)
	units := make([]component.Unit, 0)
	for _, comp := range state.Components {
		if comp.Component.InputSpec != nil && contains(comp.Component.InputSpec.Spec.OptionalActions, typ) {
			name := comp.Component.InputSpec.Spec.Name

			for _, unit := range comp.Component.Units {
				if unit.Type == client.UnitTypeInput && unit.Config != nil && unit.Config.Type == name {
					comps = append(comps, comp.Component)
					units = append(units, unit)
				}
			}
		}
	}
	return comps, units
}

func contains[T comparable](arr []T, val T) bool {
	for _, v := range arr {
		if v == val {
			return true
		}
	}
	return false
}
