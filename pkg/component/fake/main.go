// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"gopkg.in/yaml.v2"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"
)

const (
	fake = "fake"
)

func main() {
	err := run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}
}

func run() error {
	ver := client.VersionInfo{
		Name:    fake,
		Version: "1.0",
		Meta: map[string]string{
			"input": fake,
		},
	}
	c, _, err := client.NewV2FromReader(os.Stdin, ver)
	if err != nil {
		return fmt.Errorf("failed to create GRPC client: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	n := make(chan os.Signal, 1)
	signal.Notify(n, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	defer func() {
		signal.Stop(n)
		cancel()
	}()
	go func() {
		select {
		case <-n:
			cancel()
		case <-ctx.Done():
		}
	}()

	err = c.Start(ctx)
	if err != nil {
		return fmt.Errorf("failed to start GRPC client: %w", err)
	}

	s := newStateManager()
	for {
		select {
		case <-ctx.Done():
			return nil
		case change := <-c.UnitChanges():
			switch change.Type {
			case client.UnitChangedAdded:
				s.added(change.Unit)
			case client.UnitChangedModified:
				s.modified(change.Unit)
			case client.UnitChangedRemoved:
				s.removed(change.Unit)
			}
		case err := <-c.Errors():
			if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, io.EOF) {
				fmt.Fprintf(os.Stderr, "GRPC client error: %+v\n", err)
			}
		}
	}
}

type unitKey struct {
	unitType client.UnitType
	unitID   string
}

type stateManager struct {
	units map[unitKey]runningUnit
}

func newStateManager() *stateManager {
	return &stateManager{units: make(map[unitKey]runningUnit)}
}

func (s *stateManager) added(unit *client.Unit) {
	k := newUnitKey(unit)
	_, ok := s.units[k]
	if ok {
		_ = unit.UpdateState(client.UnitStateFailed, "Error: duplicate unit", nil)
		return
	}
	r, err := newRunningUnit(unit)
	if err != nil {
		_ = unit.UpdateState(client.UnitStateFailed, fmt.Sprintf("Error: %s", err), nil)
		return
	}
	s.units[k] = r
}

func (s *stateManager) modified(unit *client.Unit) {
	existing, ok := s.units[newUnitKey(unit)]
	if !ok {
		_ = unit.UpdateState(client.UnitStateFailed, "Error: unknown unit", nil)
		return
	}
	err := existing.Update(unit)
	if err != nil {
		_ = unit.UpdateState(client.UnitStateFailed, fmt.Sprintf("Error: %s", err), nil)
	}
}

func (s *stateManager) removed(unit *client.Unit) {
	k := newUnitKey(unit)
	_, ok := s.units[k]
	if !ok {
		return
	}
	delete(s.units, k)
}

type runningUnit interface {
	Unit() *client.Unit
	Update(u *client.Unit) error
}

type fakeInput struct {
	unit *client.Unit
	cfg  inputConfig

	state    client.UnitState
	stateMsg string
}

func newFakeInput(unit *client.Unit, cfg inputConfig) *fakeInput {
	i := &fakeInput{
		unit:     unit,
		cfg:      cfg,
		state:    cfg.State,
		stateMsg: cfg.Message,
	}
	unit.RegisterAction(&stateSetterAction{i})
	unit.RegisterAction(&killAction{})
	_ = unit.UpdateState(i.state, i.stateMsg, nil)
	return i
}

func (f *fakeInput) Unit() *client.Unit {
	return f.unit
}

func (f *fakeInput) Update(u *client.Unit) error {
	expected, config := u.Expected()
	if expected == client.UnitStateStopped {
		// agent is requesting this input to stop
		_ = u.UpdateState(client.UnitStateStopping, "Stopping", nil)
		go func() {
			<-time.After(1 * time.Second)
			_ = u.UpdateState(client.UnitStateStopped, "Stopped", nil)
		}()
		return nil
	}

	var cfg map[string]interface{}
	err := yaml.Unmarshal([]byte(config), &cfg)
	if err != nil {
		return fmt.Errorf("failed to unmarshal YAML: %w", err)
	}
	unitType, ok := cfg["type"]
	if !ok {
		return fmt.Errorf("unit missing config type")
	}
	if unitType != fake {
		return fmt.Errorf("unit type changed with the same unit ID: %s", unitType)
	}

	state, stateMsg, err := getStateFromMap(cfg)
	if err != nil {
		return fmt.Errorf("unit config parsing error: %w", err)
	}
	f.state = state
	f.stateMsg = stateMsg
	_ = u.UpdateState(f.state, f.stateMsg, nil)
	return nil
}

type stateSetterAction struct {
	input *fakeInput
}

func (s *stateSetterAction) Name() string {
	return "set_state"
}

func (s *stateSetterAction) Execute(_ context.Context, params map[string]interface{}) (map[string]interface{}, error) {
	state, stateMsg, err := getStateFromMap(params)
	if err != nil {
		return nil, err
	}
	s.input.state = state
	s.input.stateMsg = stateMsg
	_ = s.input.unit.UpdateState(s.input.state, s.input.stateMsg, nil)
	return nil, nil
}

type killAction struct {
}

func (s *killAction) Name() string {
	return "kill"
}

func (s *killAction) Execute(_ context.Context, params map[string]interface{}) (map[string]interface{}, error) {
	os.Exit(1)
	return nil, nil
}

func newRunningUnit(unit *client.Unit) (runningUnit, error) {
	_, config := unit.Expected()
	var cfg inputConfig
	err := yaml.Unmarshal([]byte(config), &cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal YAML: %w", err)
	}
	if cfg.Type == "" {
		return nil, fmt.Errorf("unit config type empty")
	}
	switch cfg.Type {
	case fake:
		return newFakeInput(unit, cfg), nil
	}
	return nil, fmt.Errorf("unknown unit config type: %s", cfg.Type)
}

func newUnitKey(unit *client.Unit) unitKey {
	return unitKey{
		unitType: unit.Type(),
		unitID:   unit.ID(),
	}
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

type inputConfig struct {
	Type    string           `json:"type" yaml:"type"`
	State   client.UnitState `json:"state" yaml:"state"`
	Message string           `json:"message" yaml:"message"`
}
