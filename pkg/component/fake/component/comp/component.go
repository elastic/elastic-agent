// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package comp

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/rs/zerolog"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/elastic/elastic-agent-client/v7/pkg/proto"
)

const (
	Fake              = "fake"
	FakeIsolatedUnits = "fake-isolated-units"
	FakeOutput        = "fake-output"
	APM               = "fake-apm"

	healthyMsg  = "Healthy"
	stoppingMsg = "Stopping"
	stoppedMsg  = "Stopped"
)

type StateManager struct {
	logger zerolog.Logger
	inputs map[string]runningUnit
	output runningUnit
}

func NewStateManager(logger zerolog.Logger) *StateManager {
	return &StateManager{logger: logger, inputs: make(map[string]runningUnit)}
}

func (s *StateManager) Added(unit *client.Unit) {
	if unit.Type() == client.UnitTypeOutput {
		if s.output != nil {
			_ = unit.UpdateState(client.UnitStateFailed, "Error: duplicate output unit; only supports one", nil)
			return
		}
		r, err := newRunningUnit(s.logger, s, unit)
		if err != nil {
			_ = unit.UpdateState(client.UnitStateFailed, fmt.Sprintf("Error: %s", err), nil)
			return
		}
		s.output = r
		return
	}

	_, ok := s.inputs[unit.ID()]
	if ok {
		_ = unit.UpdateState(client.UnitStateFailed, "Error: duplicate input unit", nil)
		return
	}
	r, err := newRunningUnit(s.logger, s, unit)
	if err != nil {
		_ = unit.UpdateState(client.UnitStateFailed, fmt.Sprintf("Error: %s", err), nil)
		return
	}
	s.inputs[unit.ID()] = r
}

func (s *StateManager) Modified(change client.UnitChanged) {
	unit := change.Unit
	switch unit.Type() {
	case client.UnitTypeOutput:
		if s.output == nil {
			_ = unit.UpdateState(client.UnitStateFailed, "Error: modified a non-existing output unit", nil)
			return
		}
		err := s.output.Update(unit, client.TriggeredNothing)
		if err != nil {
			_ = unit.UpdateState(client.UnitStateFailed, fmt.Sprintf("Error: %s", err), nil)
		}
		return

	case client.UnitTypeInput:
		existingInput, ok := s.inputs[unit.ID()]
		if !ok {
			_ = unit.UpdateState(client.UnitStateFailed, "Error: unknown unit", nil)
			return
		}

		err := existingInput.Update(unit, change.Triggers)
		if err != nil {
			_ = unit.UpdateState(client.UnitStateFailed, fmt.Sprintf("Error: %s", err), nil)
		}

		return
	}
}

func (s *StateManager) Removed(unit *client.Unit) {
	if unit.Type() == client.UnitTypeOutput {
		if s.output != nil {
			s.output = nil
		}
		return
	}

	_, ok := s.inputs[unit.ID()]
	if !ok {
		return
	}
	delete(s.inputs, unit.ID())
}

type runningUnit interface {
	Unit() *client.Unit
	Update(u *client.Unit, triggers client.Trigger) error
}

type fakeInput struct {
	logger  zerolog.Logger
	manager *StateManager
	unit    *client.Unit
	cfg     *proto.UnitExpectedConfig

	state    client.UnitState
	stateMsg string

	features        *proto.Features
	apmConfig       *proto.APMConfig
	canceller       context.CancelFunc
	killerCanceller context.CancelFunc
}

func newFakeInput(logger zerolog.Logger, logLevel client.UnitLogLevel, manager *StateManager, unit *client.Unit, cfg *proto.UnitExpectedConfig) (*fakeInput, error) {
	logger = logger.Level(toZerologLevel(logLevel))
	state, msg, err := getStateFromConfig(cfg)
	if err != nil {
		return nil, err
	}

	i := &fakeInput{
		logger:    logger,
		manager:   manager,
		unit:      unit,
		cfg:       cfg,
		state:     state,
		stateMsg:  msg,
		apmConfig: unit.Expected().APMConfig,
	}

	logger.Trace().Msg("registering set_state action for unit")
	unit.RegisterAction(&stateSetterAction{i})
	logger.Trace().Msg("registering kill action for unit")
	unit.RegisterAction(&killAction{i.logger})
	logger.Trace().Msg("registering " + ActionRetrieveFeatures + " action for unit")
	unit.RegisterAction(&retrieveFeaturesAction{i})
	logger.Trace().Msg("registering " + ActionRetrieveAPMConfig + " action for unit")
	unit.RegisterAction(&retrieveAPMConfigAction{i})

	logger.Debug().
		Str("state", i.state.String()).
		Str("message", i.stateMsg).Msg("updating unit state")
	_ = unit.UpdateState(i.state, i.stateMsg, nil)

	logTimer := 10 * time.Second
	if logTimerValue, ok := cfg.Source.Fields["log_timer"]; ok {
		logTimeStr := logTimerValue.GetStringValue()
		if logTimeStr != "" {
			logTimer, err = time.ParseDuration(logTimeStr)
			if err != nil {
				return nil, err
			}
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		t := time.NewTicker(logTimer)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				logger.Trace().Dur("log_timer", logTimer).Msg("trace log ticker")
			}
		}
	}()

	i.canceller = cancel
	i.parseConfig(cfg)
	return i, nil
}

func (f *fakeInput) Unit() *client.Unit {
	return f.unit
}

func (f *fakeInput) Update(u *client.Unit, triggers client.Trigger) error {
	expected := u.Expected()
	if expected.State == client.UnitStateStopped {
		// agent is requesting this input to stop
		f.logger.Debug().
			Str("state", client.UnitStateStopping.String()).
			Str("message", stoppingMsg).
			Msg("updating unit state")
		_ = u.UpdateState(client.UnitStateStopping, stoppingMsg, nil)
		f.canceller()
		go func() {
			<-time.After(1 * time.Second)
			f.logger.Debug().
				Str("state", client.UnitStateStopped.String()).
				Str("message", stoppedMsg).
				Msg("updating unit state")
			_ = u.UpdateState(client.UnitStateStopped, stoppedMsg, nil)
		}()
		return nil
	}

	if expected.Config.Type == "" {
		return fmt.Errorf("unit missing config type")
	}
	if expected.Config.Type != Fake && expected.Config.Type != FakeIsolatedUnits {
		return fmt.Errorf("unit type changed with the same unit ID: %s",
			expected.Config.Type)
	}

	f.parseConfig(expected.Config)
	state, stateMsg, err := getStateFromConfig(expected.Config)
	if err != nil {
		return fmt.Errorf("unit config parsing error: %w", err)
	}

	f.state = state
	f.stateMsg = stateMsg
	f.logger.Debug().
		Str("state", f.state.String()).
		Str("message", f.stateMsg).
		Msg("updating unit state")
	_ = u.UpdateState(f.state, f.stateMsg, nil)

	if triggers&client.TriggeredFeatureChange == client.TriggeredFeatureChange {
		f.logger.Info().
			Interface("features", expected.Features).
			Msg("updating features")
		f.features = &proto.Features{
			Source: nil,
			Fqdn:   &proto.FQDNFeature{Enabled: expected.Features.Fqdn.Enabled},
		}
	}

	if triggers&client.TriggeredAPMChange == client.TriggeredAPMChange {
		f.logger.Info().
			Interface("apmConfig", expected.APMConfig).
			Msg("updating apm configuration")
		f.apmConfig = expected.APMConfig
	}

	return nil
}

func (f *fakeInput) parseConfig(config *proto.UnitExpectedConfig) {
	// handle a case for killing the component when the pid of the component
	// matches the current running PID
	cfg := config.Source.AsMap()
	killPIDRaw, kill := cfg["kill"]
	if kill {
		f.maybeKill(killPIDRaw)
	}

	// handle a case where random killing of the component is enabled
	_, killOnInterval := cfg["kill_on_interval"]
	f.logger.Trace().Bool("kill_on_interval", killOnInterval).Msg("kill_on_interval config set value")
	if killOnInterval {
		f.runKiller()
	} else {
		f.stopKiller()
	}
}

func (f *fakeInput) maybeKill(pidRaw interface{}) {
	if killPID, ok := pidRaw.(string); ok {
		if pid, err := strconv.Atoi(killPID); err == nil {
			if pid == os.Getpid() {
				f.logger.Warn().Msg("killing from config pid")
				os.Exit(1)
			}
		}
	}
}

func (f *fakeInput) runKiller() {
	if f.killerCanceller != nil {
		// already running
		return
	}
	f.logger.Info().Msg("starting interval killer")
	ctx, canceller := context.WithCancel(context.Background())
	f.killerCanceller = canceller
	go func() {
		t := time.NewTimer(500 * time.Millisecond)
		defer t.Stop()
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			f.logger.Warn().Msg("killer performing kill")
			os.Exit(1)
		}
	}()
}

func (f *fakeInput) stopKiller() {
	if f.killerCanceller != nil {
		f.logger.Trace().Msg("stopping interval killer")
		f.killerCanceller()
		f.killerCanceller = nil
	}
}

type fakeOutput struct {
	logger  zerolog.Logger
	manager *StateManager
	unit    *client.Unit
	cfg     *proto.UnitExpectedConfig
}

func newFakeOutput(logger zerolog.Logger, logLevel client.UnitLogLevel, manager *StateManager, unit *client.Unit, cfg *proto.UnitExpectedConfig) (*fakeOutput, error) {
	logger = logger.Level(toZerologLevel(logLevel))

	f := &fakeOutput{
		logger:  logger,
		manager: manager,
		unit:    unit,
		cfg:     cfg,
	}

	f.logger.Debug().
		Str("state", client.UnitStateHealthy.String()).
		Str("message", healthyMsg).
		Msg("updating unit state")
	_ = unit.UpdateState(client.UnitStateHealthy, healthyMsg, nil)

	return f, nil
}

func (f *fakeOutput) Unit() *client.Unit {
	return f.unit
}

func (f *fakeOutput) Update(u *client.Unit, _ client.Trigger) error {
	expected := u.Expected()
	if expected.State == client.UnitStateStopped {
		// agent is requesting this input to stop
		f.logger.Debug().
			Str("state", client.UnitStateStopping.String()).
			Str("message", stoppingMsg).
			Msg("updating unit state")
		_ = u.UpdateState(client.UnitStateStopping, stoppingMsg, nil)
		go func() {
			<-time.After(1 * time.Second)
			f.logger.Debug().
				Str("state", client.UnitStateStopped.String()).
				Str("message", stoppedMsg).
				Msg("updating unit state")
			_ = u.UpdateState(client.UnitStateStopped, stoppedMsg, nil)
		}()
		return nil
	}
	f.logger.Debug().
		Str("state", client.UnitStateHealthy.String()).
		Str("message", healthyMsg).
		Msg("updating unit state")
	_ = u.UpdateState(client.UnitStateHealthy, healthyMsg, nil)
	return nil
}

func getStateFromConfig(cfg *proto.UnitExpectedConfig) (client.UnitState, string, error) {
	return getStateFromMap(cfg.Source.AsMap())
}

func getStateFromMap(cfg map[string]interface{}) (client.UnitState, string, error) {
	state, ok := cfg["state"]
	if !ok {
		return client.UnitStateStarting, "", errors.New("missing required state parameter")
	}
	stateTypeI, ok := state.(int)
	if !ok {
		// try float64 (JSON) does it differently than YAML
		stateTypeF, ok := state.(float64)
		if !ok {
			return client.UnitStateStarting, "", fmt.Errorf("state parameter is not a valid unit state: %T", state)
		}
		stateTypeI = int(stateTypeF)
	}
	stateType := client.UnitState(stateTypeI)
	stateMsgStr := ""
	stateMsg, ok := cfg["message"]
	if ok {
		stateMsgStr, _ = stateMsg.(string)
	}
	return stateType, stateMsgStr, nil
}

func toZerologLevel(level client.UnitLogLevel) zerolog.Level {
	switch level {
	case client.UnitLogLevelError:
		return zerolog.ErrorLevel
	case client.UnitLogLevelWarn:
		return zerolog.WarnLevel
	case client.UnitLogLevelInfo:
		return zerolog.InfoLevel
	case client.UnitLogLevelDebug:
		return zerolog.DebugLevel
	case client.UnitLogLevelTrace:
		return zerolog.TraceLevel
	}
	return zerolog.InfoLevel
}
