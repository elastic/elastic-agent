// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package comp

import (
	"context"
	"fmt"
	"os"

	"github.com/rs/zerolog"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"
)

const ActionRetrieveFeatures = "retrieve_features"
const ActionRetrieveAPMConfig = "retrieve_apm_config"

type retrieveFeaturesAction struct {
	input *fakeInput
}

type stateSetterAction struct {
	input *fakeInput
}

type killAction struct {
	logger zerolog.Logger
}

type retrieveAPMConfigAction struct {
	input *fakeInput
}

func (s *stateSetterAction) Name() string {
	return "set_state"
}

func (s *stateSetterAction) Execute(_ context.Context, params map[string]interface{}) (map[string]interface{}, error) {
	s.input.logger.Trace().Msg("executing set_state action")
	state, stateMsg, err := getStateFromMap(params)
	if err != nil {
		return nil, err
	}
	s.input.state = state
	s.input.stateMsg = stateMsg
	s.input.logger.Debug().Str("state", s.input.state.String()).Str("message", s.input.stateMsg).Msg("updating unit state")
	_ = s.input.unit.UpdateState(s.input.state, s.input.stateMsg, nil)
	return nil, nil
}

func (a *retrieveFeaturesAction) Name() string {
	return ActionRetrieveFeatures
}

func (a *retrieveFeaturesAction) Execute(
	_ context.Context,
	_ map[string]interface{}) (map[string]interface{}, error) {

	a.input.logger.Info().Msg("executing " + ActionRetrieveFeatures + " action")

	return map[string]interface{}{"features": a.input.features}, nil
}

func (s *killAction) Name() string {
	return "kill"
}

func (s *killAction) Execute(_ context.Context, _ map[string]interface{}) (map[string]interface{}, error) {
	s.logger.Trace().Msg("executing kill action")
	os.Exit(1)
	return nil, nil
}

func newRunningUnit(logger zerolog.Logger, manager *StateManager, unit *client.Unit) (runningUnit, error) {
	expected := unit.Expected()
	if expected.Config.Type == "" {
		return nil, fmt.Errorf("unit config type empty")
	}
	if unit.Type() == client.UnitTypeOutput {
		switch expected.Config.Type {
		case FakeOutput:
			return newFakeOutput(logger, expected.LogLevel, manager, unit, expected.Config)
		}
		return nil, fmt.Errorf("unknown output unit config type: %s",
			expected.Config.Type)
	}
	switch expected.Config.Type {
	case Fake, FakeIsolatedUnits:
		return newFakeInput(logger, expected.LogLevel, manager, unit, expected.Config)
	case APM:
		return newFakeAPMInput(logger, expected.LogLevel, unit)
	}
	return nil, fmt.Errorf("unknown input unit config type: %s",
		expected.Config.Type)
}

func (a *retrieveAPMConfigAction) Name() string {
	return ActionRetrieveAPMConfig
}

func (a *retrieveAPMConfigAction) Execute(
	_ context.Context,
	_ map[string]interface{}) (map[string]interface{}, error) {

	a.input.logger.Info().Msg("executing " + ActionRetrieveAPMConfig + " action")
	a.input.logger.Debug().Msgf("stored apm config %v", a.input.apmConfig)
	if a.input.apmConfig == nil {
		return map[string]interface{}{"apm": nil}, nil
	}
	marshaledBytes, err := protojson.Marshal(a.input.apmConfig)
	return map[string]interface{}{"apm": string(marshaledBytes)}, err
}
