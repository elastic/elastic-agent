// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package comp

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/rs/zerolog"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"
)

type stateSetterAction struct {
	input *fakeInput
}

type sendEventAction struct {
	input *fakeInput
}

type killAction struct {
	logger zerolog.Logger
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

func (s *sendEventAction) Name() string {
	return "send_event"
}

func (s *sendEventAction) Execute(_ context.Context, params map[string]interface{}) (map[string]interface{}, error) {
	const (
		timeoutField   = "timeout"
		timeoutDefault = 3 * time.Second
	)

	s.input.logger.Trace().Msg("executing send_event action")

	// timeout is taken from the action to define the timeout
	timeout := timeoutDefault
	if timeoutRaw, ok := params[timeoutField]; ok {
		if timeoutStr, ok := timeoutRaw.(string); ok {
			dur, err := time.ParseDuration(timeoutStr)
			if err != nil {
				return nil, fmt.Errorf("failed to parse timeout duration: %w", err)
			}
			timeout = dur
		}
	}

	if s.input.manager.output != nil {
		output, ok := s.input.manager.output.(*fakeShipperOutput)
		if !ok {
			return nil, fmt.Errorf("output is not fake-shipper output, cannot send event, got type %T", s.input.manager.output)
		}
		err := output.sendEvent(params, timeout)
		if err != nil {
			return nil, err
		}
		return nil, nil
	}
	return nil, errors.New("no output configured to send event")
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
	_, logLevel, config := unit.Expected()
	if config.Type == "" {
		return nil, fmt.Errorf("unit config type empty")
	}
	if unit.Type() == client.UnitTypeOutput {
		switch config.Type {
		case fakeShipper:
			return newFakeShipperOutput(logger, logLevel, unit, config)
		}
		return nil, fmt.Errorf("unknown output unit config type: %s", config.Type)
	}
	switch config.Type {
	case Fake:
		return newFakeInput(logger, logLevel, manager, unit, config)
	}
	return nil, fmt.Errorf("unknown input unit config type: %s", config.Type)
}
