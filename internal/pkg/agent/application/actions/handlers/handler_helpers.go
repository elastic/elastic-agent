// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package handlers

import (
	"context"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/elastic/elastic-agent-libs/logp"
	"golang.org/x/sync/errgroup"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/coordinator/state"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi"
	"github.com/elastic/elastic-agent/pkg/component"
)

type actionCoordinator interface {
	State() state.State
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

func dispatchActionInParallel(ctx context.Context, log *logp.Logger, action dispatchableAction, comps []component.Component, units []component.Unit, performAction performActionFunc) error {
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

	// Iterate through found components and forward the UNENROLL action
	for i := 0; i < len(comps); i++ {
		g.Go(func(idx int) func() error {
			comp := comps[i]
			unit := units[i]
			return func() error {
				log.Debugf("Dispatch %v action to %v", actionType, unit.Config.Type)
				res, err := performAction(ctx, comp, unit, unit.Config.Type, params)
				if err != nil {
					log.Warnf("%v failed to dispatch to %v, err: %v", actionType, comp.ID, err)
					return err
				} else {
					strErr := readMapString(res, "error", "")
					if strErr != "" {
						log.Warnf("%v failed for %v, err: %v", actionType, comp.ID, strErr)
						return errors.New(strErr)
					}
				}
				return nil
			}
		}(i))
	}

	return g.Wait()
}

func findMatchingUnitsByActionType(state state.State, typ string) ([]component.Component, []component.Unit) {
	comps := make([]component.Component, 0)
	units := make([]component.Unit, 0)
	for _, comp := range state.Components {
		if comp.Component.InputSpec != nil && contains(comp.Component.InputSpec.Spec.ProxiedActions, typ) {
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
