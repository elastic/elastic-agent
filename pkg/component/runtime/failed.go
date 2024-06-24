// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package runtime

import (
	"context"
	"errors"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"

	"github.com/elastic/elastic-agent/pkg/component"
)

// failedRuntime is used for a component that has an error from the component loader.
type failedRuntime struct {
	ch      chan ComponentState
	current component.Component
	done    chan bool
}

// newFailedRuntime creates a runtime for a component that has an error from the component loader.
func newFailedRuntime(comp component.Component) (*failedRuntime, error) {
	if comp.Err == nil {
		return nil, errors.New("must be a component that has a defined error")
	}
	return &failedRuntime{
		ch:      make(chan ComponentState),
		current: comp,
		done:    make(chan bool),
	}, nil
}

// Run runs the runtime for a component that got an error from the component loader.
func (c *failedRuntime) Run(ctx context.Context, _ Communicator) error {
	// state is hard coded to failed
	c.ch <- createState(c.current, false)
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-c.done:
		// set to stopped as soon as done is given
		c.ch <- createState(c.current, true)
	}
	<-ctx.Done()
	return ctx.Err()
}

// Watch returns the watch channel.
func (c *failedRuntime) Watch() <-chan ComponentState {
	return c.ch
}

// Start does nothing.
func (c *failedRuntime) Start() error {
	return nil
}

// Update updates the component state.
func (c *failedRuntime) Update(comp component.Component) error {
	if comp.Err == nil {
		return errors.New("cannot update to a component without a defined error")
	}
	c.current = comp
	return nil
}

// Stop marks it stopped.
func (c *failedRuntime) Stop() error {
	go func() {
		close(c.done)
	}()
	return nil
}

// Teardown marks it stopped.
func (c *failedRuntime) Teardown(_ *component.Signed) error {
	return c.Stop()
}

func createState(comp component.Component, done bool) ComponentState {
	state := client.UnitStateFailed
	if done {
		state = client.UnitStateStopped
	}
	unitErrs := make(map[ComponentUnitKey]ComponentUnitState)
	for _, unit := range comp.Units {
		key := ComponentUnitKey{
			UnitType: unit.Type,
			UnitID:   unit.ID,
		}
		unitErrs[key] = ComponentUnitState{
			State:   state,
			Message: comp.Err.Error(),
			Payload: nil,
		}
	}
	return ComponentState{
		State:     state,
		Message:   comp.Err.Error(),
		Units:     unitErrs,
		Features:  comp.Features,
		Component: comp.Component,
	}
}
