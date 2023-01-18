// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package main

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/rs/zerolog"
	"golang.org/x/sync/errgroup"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/elastic/elastic-agent-client/v7/pkg/proto"

	"github.com/elastic/elastic-agent/pkg/component/fake/common"
)

const (
	fake        = "fake"
	fakeShipper = "fake-shipper"

	configuringMsg = "Configuring"
	stoppingMsg    = "Stopping"
	stoppedMsg     = "Stopped"
)

func main() {
	err := run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}
}

func run() error {
	logger := zerolog.New(os.Stderr).Level(zerolog.TraceLevel).With().Timestamp().Logger()
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

	s := newStateManager(logger)
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

type stateManager struct {
	logger zerolog.Logger
	inputs map[string]runningUnit
	output runningUnit
}

func newStateManager(logger zerolog.Logger) *stateManager {
	return &stateManager{logger: logger, inputs: make(map[string]runningUnit)}
}

func (s *stateManager) added(unit *client.Unit) {
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

func (s *stateManager) modified(unit *client.Unit) {
	if unit.Type() == client.UnitTypeOutput {
		if s.output == nil {
			_ = unit.UpdateState(client.UnitStateFailed, "Error: modified a non-existing output unit", nil)
			return
		}
		err := s.output.Update(unit)
		if err != nil {
			_ = unit.UpdateState(client.UnitStateFailed, fmt.Sprintf("Error: %s", err), nil)
		}
		return
	}

	existing, ok := s.inputs[unit.ID()]
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
	Update(u *client.Unit) error
}

type sendEvent struct {
	evt     *common.Event
	timeout time.Duration
	doneCh  chan error
}

type fakeShipperOutput struct {
	logger zerolog.Logger
	unit   *client.Unit
	cfg    *proto.UnitExpectedConfig

	evtCh chan sendEvent

	runner    errgroup.Group
	canceller context.CancelFunc
}

func newFakeShipperOutput(logger zerolog.Logger, logLevel client.UnitLogLevel, unit *client.Unit, cfg *proto.UnitExpectedConfig) (*fakeShipperOutput, error) {
	logger = logger.Level(toZerologLevel(logLevel))

	f := &fakeShipperOutput{
		logger: logger,
		unit:   unit,
		cfg:    cfg,
		evtCh:  make(chan sendEvent),
	}

	logger.Trace().Msg("registering kill action for unit")
	unit.RegisterAction(&killAction{f.logger})

	f.start(unit, cfg)

	return f, nil
}

func (f *fakeShipperOutput) Unit() *client.Unit {
	return f.unit
}

func (f *fakeShipperOutput) Update(u *client.Unit) error {
	expected, _, config := u.Expected()
	if expected == client.UnitStateStopped {
		// agent is requesting this input to stop
		f.logger.Debug().Str("state", client.UnitStateStopping.String()).Str("message", stoppingMsg).Msg("updating unit state")
		_ = u.UpdateState(client.UnitStateStopping, stoppingMsg, nil)
		go func() {
			f.stop()
			f.logger.Debug().Str("state", client.UnitStateStopped.String()).Str("message", stoppedMsg).Msg("updating unit state")
			_ = u.UpdateState(client.UnitStateStopped, stoppedMsg, nil)
		}()
		return nil
	}

	if config.Type == "" {
		return fmt.Errorf("unit missing config type")
	}
	if config.Type != fakeShipper {
		return fmt.Errorf("unit type changed with the same unit ID: %s", config.Type)
	}

	f.stop()
	f.cfg = config
	f.start(u, config)

	return nil
}

func (f *fakeShipperOutput) sendEvent(event map[string]interface{}, timeout time.Duration) error {
	content, err := structpb.NewStruct(event)
	if err != nil {
		return err
	}
	evt := &common.Event{
		Generated: timestamppb.Now(),
		Content:   content,
	}
	doneCh := make(chan error)
	f.evtCh <- sendEvent{
		evt:     evt,
		timeout: timeout,
		doneCh:  doneCh,
	}
	return <-doneCh
}

func (f *fakeShipperOutput) start(unit *client.Unit, cfg *proto.UnitExpectedConfig) {
	ctx, cancel := context.WithCancel(context.Background())
	f.canceller = cancel
	f.runner.Go(func() error {
		for {
			err := f.run(ctx, unit, cfg)
			if err != nil {
				if errors.Is(err, context.Canceled) {
					// don't restart
					return err
				}
				// restartable error
				f.logger.Error().Err(err)
				_ = unit.UpdateState(client.UnitStateFailed, err.Error(), nil)
				// delay restart
				<-time.After(time.Second)
			}
		}
	})
}

func (f *fakeShipperOutput) stop() {
	if f.canceller != nil {
		f.canceller()
		f.canceller = nil
		f.runner.Wait()
	}
}

func (f *fakeShipperOutput) run(ctx context.Context, unit *client.Unit, cfg *proto.UnitExpectedConfig) error {
	f.logger.Debug().Str("state", client.UnitStateConfiguring.String()).Str("message", configuringMsg).Msg("restarting shipper output")
	_ = unit.UpdateState(client.UnitStateConfiguring, configuringMsg, nil)

	shipperCfg, err := common.ParseFakeShipperConfig(cfg)
	if err != nil {
		return fmt.Errorf("failed to parse fake shipper config: %w", err)
	}
	if shipperCfg.TLS == nil || len(shipperCfg.TLS.CAs) == 0 {
		return fmt.Errorf("fake shipper ssl configuration missing")
	}
	certPool := x509.NewCertPool()
	for _, certPEM := range shipperCfg.TLS.CAs {
		if ok := certPool.AppendCertsFromPEM([]byte(certPEM)); !ok {
			return errors.New("failed to append CA for shipper connection")
		}
	}
	conn, err := dialContext(ctx, shipperCfg.Server, certPool, unit.ID())
	if err != nil {
		return fmt.Errorf("grpc client failed to connect: %w", err)
	}
	defer conn.Close()

	connectedMsg := fmt.Sprintf("GRPC fake event pipe connected %q", shipperCfg.Server)
	f.logger.Debug().Str("state", client.UnitStateHealthy.String()).Str("message", connectedMsg).Msg("connected to output")
	_ = unit.UpdateState(client.UnitStateHealthy, connectedMsg, nil)

	client := common.NewFakeEventProtocolClient(conn)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case evt := <-f.evtCh:
			evtCtx, evtCanceller := context.WithTimeout(ctx, evt.timeout)
			_, err := client.SendEvent(evtCtx, evt.evt, grpc.WaitForReady(true))
			evtCanceller()
			evt.doneCh <- err
		}
	}
}

type fakeInput struct {
	logger  zerolog.Logger
	manager *stateManager
	unit    *client.Unit
	cfg     *proto.UnitExpectedConfig

	state    client.UnitState
	stateMsg string

	canceller       context.CancelFunc
	killerCanceller context.CancelFunc
}

func newFakeInput(logger zerolog.Logger, logLevel client.UnitLogLevel, manager *stateManager, unit *client.Unit, cfg *proto.UnitExpectedConfig) (*fakeInput, error) {
	logger = logger.Level(toZerologLevel(logLevel))
	state, msg, err := getStateFromConfig(cfg)
	if err != nil {
		return nil, err
	}

	i := &fakeInput{
		logger:   logger,
		manager:  manager,
		unit:     unit,
		cfg:      cfg,
		state:    state,
		stateMsg: msg,
	}

	logger.Trace().Msg("registering set_state action for unit")
	unit.RegisterAction(&stateSetterAction{i})
	logger.Trace().Msg("registering send_event action for unit")
	unit.RegisterAction(&sendEventAction{i})
	logger.Trace().Msg("registering kill action for unit")
	unit.RegisterAction(&killAction{i.logger})
	logger.Debug().Str("state", i.state.String()).Str("message", i.stateMsg).Msg("updating unit state")
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

func (f *fakeInput) Update(u *client.Unit) error {
	expected, _, config := u.Expected()
	if expected == client.UnitStateStopped {
		// agent is requesting this input to stop
		f.logger.Debug().Str("state", client.UnitStateStopping.String()).Str("message", stoppingMsg).Msg("updating unit state")
		_ = u.UpdateState(client.UnitStateStopping, stoppingMsg, nil)
		f.canceller()
		go func() {
			<-time.After(1 * time.Second)
			f.logger.Debug().Str("state", client.UnitStateStopped.String()).Str("message", stoppedMsg).Msg("updating unit state")
			_ = u.UpdateState(client.UnitStateStopped, stoppedMsg, nil)
		}()
		return nil
	}

	if config.Type == "" {
		return fmt.Errorf("unit missing config type")
	}
	if config.Type != fake {
		return fmt.Errorf("unit type changed with the same unit ID: %s", config.Type)
	}

	f.parseConfig(config)
	state, stateMsg, err := getStateFromConfig(config)
	if err != nil {
		return fmt.Errorf("unit config parsing error: %w", err)
	}
	f.state = state
	f.stateMsg = stateMsg
	f.logger.Debug().Str("state", f.state.String()).Str("message", f.stateMsg).Msg("updating unit state")
	_ = u.UpdateState(f.state, f.stateMsg, nil)
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
	_, killer := cfg["killer"]
	f.logger.Trace().Bool("killer", killer).Msg("killer config set value")
	if killer {
		f.logger.Info().Msg("starting interval killer")
		f.runKiller()
	} else {
		f.logger.Info().Msg("stopping interval killer")
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
		f.killerCanceller()
		f.killerCanceller = nil
	}
}

type stateSetterAction struct {
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

type sendEventAction struct {
	input *fakeInput
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
	case fake:
		return newFakeInput(logger, logLevel, manager, unit, config)
	}
	return nil, fmt.Errorf("unknown input unit config type: %s", config.Type)
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
