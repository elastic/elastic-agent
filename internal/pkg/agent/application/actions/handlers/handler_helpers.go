// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package handlers

import (
	"context"

	"golang.org/x/sync/errgroup"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/elastic/elastic-agent-libs/logp"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/coordinator"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi"
	"github.com/elastic/elastic-agent/pkg/component"
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

func dispatchActionInParallel(ctx context.Context, log *logp.Logger, action dispatchableAction, ucs []unitWithComponent, performAction performActionFunc) error {
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
		log.Debugf("Dispatch %v action to %v", actionType, uc.unit.Config.Type)
		res, err := performAction(ctx, uc.component, uc.unit, uc.unit.Config.Type, params)
		if err != nil {
			log.Warnf("%v failed to dispatch to %v, err: %v", actionType, uc.component.ID, err)
			return err
		}

		strErr := readMapString(res, "error", "")
		if strErr != "" {
			log.Warnf("%v failed for %v, err: %v", actionType, uc.component.ID, strErr)
			return errors.New(strErr)
		}
		return nil
	}

	// Iterate through the components and dispatch the action is the action type is listed in the proxied_actions
	for _, uc := range ucs {
		// Send the action to the target unit via g.Go to collect any resulting errors
		target := uc
		g.Go(func() error {
			return dispatch(target)
		})
	}

	return g.Wait()
}

func findMatchingUnitsByActionType(state coordinator.State, typ string) []unitWithComponent {
	ucs := make([]unitWithComponent, 0)
	for _, comp := range state.Components {
		if comp.Component.InputSpec != nil && contains(comp.Component.InputSpec.Spec.ProxiedActions, typ) {
			name := comp.Component.InputSpec.Spec.Name

			for _, unit := range comp.Component.Units {
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
