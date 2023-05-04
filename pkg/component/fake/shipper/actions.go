// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package main

import (
	"context"
	"fmt"
	"os"

	"github.com/rs/zerolog"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"
)

const ActionRecordEvent = "record_event"

// recordEventAction is an action that returns a result only once an event comes over the fake shipper protocol
type recordEventAction struct {
	f *fakeActionOutputRuntime
}

// killAction is an action that causes the whole component to exit (used in testing to simulate crashes)
type killAction struct {
	logger zerolog.Logger
}

func (s *killAction) Name() string {
	return "kill"
}

func (s *killAction) Execute(_ context.Context, _ map[string]interface{}) (map[string]interface{}, error) {
	s.logger.Trace().Msg("executing kill action")
	os.Exit(1)
	return nil, nil
}

func newRunningUnit(logger zerolog.Logger, manager *stateManager, unit *client.Unit) (runningUnit, error) {
	expected := unit.Expected()
	if expected.Config.Type == "" {
		return nil, fmt.Errorf("unit config type empty")
	}
	if unit.Type() == client.UnitTypeOutput {
		switch expected.Config.Type {
		case fakeActionOutput:
			return newFakeActionOutputRuntime(logger, expected.LogLevel, unit, expected.Config)
		}
		return nil, fmt.Errorf("unknown output unit config type: %s", expected.Config.Type)
	} else if unit.Type() == client.UnitTypeInput {
		switch expected.Config.Type {
		case fakeShipper:
			return newFakeShipperInput(logger, expected.LogLevel, manager, unit, expected.Config)
		}
		return nil, fmt.Errorf("unknown input unit config type: %s", expected.Config.Type)
	}
	return nil, fmt.Errorf("unknown unit type: %+v", unit.Type())
}

func newUnitKey(unit *client.Unit) unitKey {
	return unitKey{
		unitType: unit.Type(),
		unitID:   unit.ID(),
	}
}

func (r *recordEventAction) Name() string {
	return ActionRecordEvent
}

func (r *recordEventAction) Execute(ctx context.Context, params map[string]interface{}) (map[string]interface{}, error) {
	eventIDRaw, ok := params[recordActionEventID]
	if !ok {
		return nil, fmt.Errorf("missing required 'id' parameter")
	}
	eventID, ok := eventIDRaw.(string)
	if !ok {
		return nil, fmt.Errorf("'id' parameter not string type, got %T", eventIDRaw)
	}

	r.f.logger.Trace().Str(recordActionEventID, eventID).Msg("registering " + ActionRecordEvent + " action")
	c := r.f.subscribe(eventID)
	defer r.f.unsubscribe(eventID)

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case e, ok := <-c:
		r.f.logger.Trace().Fields(map[string]interface{}{
			"timestamp": e.Generated.AsTime(),
			"content":   e.Content.AsMap(),
		}).Msg("record_event action got subscribed event")
		if !ok {
			return nil, fmt.Errorf("never received event")
		}
		return map[string]interface{}{
			"timestamp": e.Generated.String(),
			"event":     e.Content.AsMap(),
		}, nil
	}
}
