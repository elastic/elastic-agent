// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package runtime

import (
	"context"
	"errors"
	"fmt"

	"github.com/kardianos/service"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/elastic/elastic-agent/pkg/component"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

// containerRuntime provides the command runtime for running a component as a container.
type containerRuntime struct {
	comp component.Component
	log  *logger.Logger

	ch       chan ComponentState
	actionCh chan actionModeSigned
	compCh   chan component.Component
	statusCh chan service.Status

	state ComponentState

	executeServiceCommandImpl executeServiceCommandFunc
}

// newContainerRuntime creates a new container runtime for the provided component.
func newContainerRuntime(comp component.Component, logger *logger.Logger) (*containerRuntime, error) {
	if comp.ShipperSpec != nil {
		return nil, errors.New("service runtime not supported for a shipper specification")
	}
	if comp.InputSpec == nil {
		return nil, errors.New("service runtime requires an input specification to be defined")
	}

	state := newComponentState(&comp)

	c := &containerRuntime{
		comp:                      comp,
		log:                       logger.Named("container_runtime"),
		ch:                        make(chan ComponentState),
		actionCh:                  make(chan actionModeSigned, 1),
		compCh:                    make(chan component.Component, 1),
		statusCh:                  make(chan service.Status),
		state:                     state,
		executeServiceCommandImpl: executeServiceCommand,
	}

	// Set initial state as STOPPED
	c.state.compState(client.UnitStateStopped, fmt.Sprintf("Stopped: %s container", c.name()))
	return c, nil
}

func (c *containerRuntime) ID() string {
	return c.comp.ID
}

// Run starts new container
func (c *containerRuntime) Run(ctx context.Context, recCh chan watchResult) error {
	c.log.Debugf("Runtime: starting component")
	recCh <- watchResult{
		Create: true,
		Comp:   c.comp,
	}
	return nil
}

// Update updates config map related to container
func (c *containerRuntime) Update(ctx context.Context, comp component.Component, recCh chan watchResult) error {
	// TODO: check smoething changed
	c.log.Debugf("Runtime: updating component")
	recCh <- watchResult{
		Update: true,
		Comp:   c.comp,
	}
	return nil
}

// Stop stops the container and cleans up
func (c *containerRuntime) Stop(ctx context.Context, recCh chan watchResult) error {
	c.log.Debugf("Runtime: stopping component")
	recCh <- watchResult{
		Stop: true,
		Comp: c.comp,
	}
	return nil
}

func (c *containerRuntime) name() string {
	return c.comp.InputSpec.Spec.Name
}
