// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package handlers

import (
	"context"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/elastic/elastic-agent-libs/logp"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/coordinator"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/internal/pkg/core/backoff"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi"
	"github.com/elastic/elastic-agent/pkg/component"
	"github.com/elastic/elastic-agent/pkg/component/runtime"
)

type actionCoordinator interface {
	State() coordinator.State
	PerformAction(ctx context.Context, comp component.Component, unit component.Unit, name string, params map[string]interface{}) (map[string]interface{}, error)
}

type upgradeCoordinator interface {
	actionCoordinator
	Upgrade(ctx context.Context, version string, sourceURI string, action *fleetapi.ActionUpgrade, skipVerifyOverride bool, pgpBytes ...string) error
}

type performActionFunc func(context.Context, component.Component, component.Unit, string, map[string]interface{}) (map[string]interface{}, error)

type dispatchableAction interface {
	MarshalMap() (map[string]interface{}, error)
	Type() string
}

type unitWithComponent struct {
	unit      component.Unit
	component component.Component
}

func findMatchingUnitsByActionType(state coordinator.State, typ string) []unitWithComponent {
	ucs := make([]unitWithComponent, 0)
	for _, comp := range state.Components {
		if comp.Component.InputSpec != nil && contains(comp.Component.InputSpec.Spec.ProxiedActions, typ) {
			name := comp.Component.InputType
			for _, unit := range comp.Component.Units {
				// All input units should match the component input type, but let's be cautious
				if unit.Type == client.UnitTypeInput && unit.Config != nil && unit.Config.Type == name {
					ucs = append(ucs, unitWithComponent{unit, comp.Component})
				}
			}
		}
	}
	return ucs
}

func contains[T comparable](arr []T, val T) bool {
	for _, v := range arr {
		if v == val {
			return true
		}
	}
	return false
}

type proxiedActionsNotifier struct {
	log           *logp.Logger
	performAction performActionFunc

	timeout    time.Duration
	minBackoff time.Duration
	maxBackoff time.Duration
}

const (
	defaultActionDispatcherTimeout    = 40 * time.Second
	defaultActionDispatcherBackoffMin = 500 * time.Millisecond
	defaultActionDispatcherBackoffMax = 10 * time.Second
)

func newProxiedActionsNotifier(log *logp.Logger, performAction performActionFunc) proxiedActionsNotifier {
	return proxiedActionsNotifier{
		log:           log,
		performAction: performAction,
		timeout:       defaultActionDispatcherTimeout,
		minBackoff:    defaultActionDispatcherBackoffMin,
		maxBackoff:    defaultActionDispatcherBackoffMax,
	}
}

func (d proxiedActionsNotifier) notify(ctx context.Context, action dispatchableAction, ucs []unitWithComponent) error {
	if action == nil {
		return nil
	}

	// Deserialize the action into map[string]interface{} for dispatching over to the apps
	params, err := action.MarshalMap()
	if err != nil {
		return err
	}

	actionType := action.Type()

	g, ctx := errgroup.WithContext(ctx)

	dispatch := func(uc unitWithComponent) error {
		if uc.unit.Config == nil {
			return nil
		}
		d.log.Debugf("Dispatch %v action to %v", actionType, uc.unit.Config.Type)
		res, err := d.performAction(ctx, uc.component, uc.unit, uc.unit.Config.Type, params)
		if err != nil {
			d.log.Debugf("%v failed to dispatch to %v, err: %v", actionType, uc.component.ID, err)
			// ErrNoUnit means that the unit is not longer available
			// This can happen if the policy change updated state while the action proxying was retried
			// Stop retrying proxying action to that unit return nil
			if errors.Is(err, runtime.ErrNoUnit) {
				d.log.Debugf("%v unit is not longer managed by runtime, possibly due to policy change", uc.component.ID)
				return nil
			}
			return err
		}

		strErr := readMapString(res, "error", "")
		if strErr != "" {
			d.log.Debugf("%v failed for %v, err: %v", actionType, uc.component.ID, strErr)
			return errors.New(strErr)
		}
		return nil
	}

	dispatchWithBackoff := func(uc unitWithComponent) error {
		ctx, cn := context.WithTimeout(ctx, d.timeout)
		defer cn()

		attempt := 1
		backExp := backoff.NewExpBackoff(ctx.Done(), d.minBackoff, d.maxBackoff)
		start := time.Now()

		for {
			err := dispatch(uc)
			if err != nil {
				if backExp.Wait() {
					d.log.Debugf("%v action dispatch to %v with backoff attempt: %v, after %v since start", actionType, uc.component.ID, attempt, time.Since(start))
					attempt++
					continue
				}
				return err
			}
			return nil
		}
	}

	// Iterate through the components and dispatch the action is the action type is listed in the proxied_actions
	for _, uc := range ucs {
		// Send the action to the target unit via g.Go to collect any resulting errors
		target := uc
		g.Go(func() error {
			return dispatchWithBackoff(target)
		})
	}

	return g.Wait()
}

// notifyUnitsOfProxiedAction dispatches actions to the units/components in parallel, with exponential backoff and timeout
func notifyUnitsOfProxiedAction(ctx context.Context, log *logp.Logger, action dispatchableAction, ucs []unitWithComponent, performAction performActionFunc) error {
	return newProxiedActionsNotifier(log, performAction).notify(ctx, action, ucs)
}
