// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"io"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/rs/zerolog"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/elastic/elastic-agent-client/v7/pkg/proto"

	"github.com/elastic/elastic-agent/pkg/component/fake/common"
)

const (
	fakeActionOutput = "fake-action-output"
	fakeShipper      = "fake-shipper"

	healthyMsg  = "Healthy"
	stoppingMsg = "Stopping"
	stoppedMsg  = "Stopped"

	recordActionEventId = "id"
)

func main() {
	err := run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}
}

func run() error {
	logger := zerolog.New(os.Stderr).With().Timestamp().Logger()
	ver := client.VersionInfo{
		Name:    fakeShipper,
		Version: "1.0",
		Meta: map[string]string{
			"shipper": fakeShipper,
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

type unitKey struct {
	unitType client.UnitType
	unitID   string
}

type stateManager struct {
	logger  zerolog.Logger
	unitsMx sync.RWMutex
	units   map[unitKey]runningUnit
}

func newStateManager(logger zerolog.Logger) *stateManager {
	return &stateManager{logger: logger, units: make(map[unitKey]runningUnit)}
}

func (s *stateManager) added(unit *client.Unit) {
	s.unitsMx.Lock()
	defer s.unitsMx.Unlock()
	k := newUnitKey(unit)
	_, ok := s.units[k]
	if ok {
		_ = unit.UpdateState(client.UnitStateFailed, "Error: duplicate unit", nil)
		return
	}
	r, err := newRunningUnit(s.logger, s, unit)
	if err != nil {
		_ = unit.UpdateState(client.UnitStateFailed, fmt.Sprintf("Error: %s", err), nil)
		return
	}
	s.units[k] = r
}

func (s *stateManager) modified(unit *client.Unit) {
	s.unitsMx.Lock()
	defer s.unitsMx.Unlock()
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
	s.unitsMx.Lock()
	defer s.unitsMx.Unlock()
	k := newUnitKey(unit)
	_, ok := s.units[k]
	if !ok {
		return
	}
	delete(s.units, k)
}

func (s *stateManager) received(ctx context.Context, event *common.Event) error {
	if event.Content == nil {
		return nil
	}
	val, ok := event.Content.Fields[recordActionEventId]
	if !ok {
		return nil
	}
	id := val.String()
	s.unitsMx.RLock()
	defer s.unitsMx.RUnlock()
	for k, u := range s.units {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if k.unitType == client.UnitTypeOutput {
			actionOutput, ok := u.(*fakeActionOutputRuntime)
			if ok {
				if actionOutput.received(ctx, id, event) {
					// caught by output
					break
				}
			}
		}
	}
	return nil
}

type runningUnit interface {
	Unit() *client.Unit
	Update(u *client.Unit) error
}

type fakeActionOutputRuntime struct {
	logger zerolog.Logger
	unit   *client.Unit
	cfg    *proto.UnitExpectedConfig

	subsMx sync.RWMutex
	subs   map[string]chan *common.Event
}

func newFakeActionOutputRuntime(logger zerolog.Logger, logLevel client.UnitLogLevel, unit *client.Unit, cfg *proto.UnitExpectedConfig) (*fakeActionOutputRuntime, error) {
	logger = logger.Level(toZerologLevel(logLevel))

	i := &fakeActionOutputRuntime{
		logger: logger,
		unit:   unit,
		cfg:    cfg,
		subs:   make(map[string]chan *common.Event),
	}

	logger.Trace().Msg("registering record-event action for unit")
	unit.RegisterAction(&recordEventAction{i})
	logger.Trace().Msg("registering kill action for unit")
	unit.RegisterAction(&killAction{logger})
	logger.Debug().Str("state", client.UnitStateHealthy.String()).Str("message", healthyMsg).Msg("updating unit state")
	_ = unit.UpdateState(client.UnitStateHealthy, healthyMsg, nil)

	return i, nil
}

func (f *fakeActionOutputRuntime) Unit() *client.Unit {
	return f.unit
}

func (f *fakeActionOutputRuntime) Update(u *client.Unit) error {
	expected, _, config := u.Expected()
	if expected == client.UnitStateStopped {
		// agent is requesting this to stop
		f.logger.Debug().Str("state", client.UnitStateStopping.String()).Str("message", stoppingMsg).Msg("updating unit state")
		_ = u.UpdateState(client.UnitStateStopping, stoppingMsg, nil)
		go func() {
			f.cleanup()
			f.logger.Debug().Str("state", client.UnitStateStopped.String()).Str("message", stoppedMsg).Msg("updating unit state")
			_ = u.UpdateState(client.UnitStateStopped, stoppedMsg, nil)
		}()
		return nil
	}

	if config.Type == "" {
		return fmt.Errorf("unit missing config type")
	}
	if config.Type != fakeActionOutput {
		return fmt.Errorf("unit type changed with the same unit ID: %s", config.Type)
	}
	// nothing to really do
	return nil
}

func (f *fakeActionOutputRuntime) subscribe(id string) <-chan *common.Event {
	f.subsMx.Lock()
	defer f.subsMx.Unlock()
	c, ok := f.subs[id]
	if ok {
		return c
	}
	c = make(chan *common.Event, 1)
	f.subs[id] = c
	return c
}

func (f *fakeActionOutputRuntime) unsubscribe(id string) {
	f.subsMx.Lock()
	defer f.subsMx.Unlock()
	c, ok := f.subs[id]
	if ok {
		close(c)
		delete(f.subs, id)
	}
}

func (f *fakeActionOutputRuntime) cleanup() {
	f.subsMx.Lock()
	defer f.subsMx.Unlock()
	for k, c := range f.subs {
		close(c)
		delete(f.subs, k)
	}
}

func (f *fakeActionOutputRuntime) received(ctx context.Context, id string, event *common.Event) bool {
	f.subsMx.RLock()
	defer f.subsMx.RUnlock()
	c, ok := f.subs[id]
	if ok {
		select {
		case <-ctx.Done():
			return false
		case c <- event:
			return true
		}
	}
	return false
}

// recordEventAction is an action that returns a result only once an event comes over the fake shipper protocol
type recordEventAction struct {
	f *fakeActionOutputRuntime
}

func (r *recordEventAction) Name() string {
	return "record-event"
}

func (r *recordEventAction) Execute(ctx context.Context, params map[string]interface{}) (map[string]interface{}, error) {
	eventIdRaw, ok := params[recordActionEventId]
	if !ok {
		return nil, fmt.Errorf("missing required 'id' parameter")
	}
	eventId, ok := eventIdRaw.(string)
	if !ok {
		return nil, fmt.Errorf("'id' parameter not string type, got %T", eventIdRaw)
	}
	r.f.logger.Trace().Str(recordActionEventId, eventId).Msg("registering record event action")
	c := r.f.subscribe(eventId)
	defer r.f.unsubscribe(eventId)
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case e, ok := <-c:
		if !ok {
			return nil, fmt.Errorf("never recieved event")
		}
		return map[string]interface{}{
			"timestamp": e.Generated.String(),
			"event":     e.Content.AsMap(),
		}, nil
	}
}

type fakeShipperInput struct {
	common.UnimplementedFakeEventProtocolServer

	logger  zerolog.Logger
	manager *stateManager
	unit    *client.Unit
	cfg     *proto.UnitExpectedConfig

	srv *grpc.Server
	wg  errgroup.Group
}

func newFakeShipperInput(logger zerolog.Logger, logLevel client.UnitLogLevel, manager *stateManager, unit *client.Unit, cfg *proto.UnitExpectedConfig) (*fakeShipperInput, error) {
	logger = logger.Level(toZerologLevel(logLevel))

	i := &fakeShipperInput{
		logger:  logger,
		manager: manager,
		unit:    unit,
		cfg:     cfg,
	}

	srvCfg, err := common.ParseFakeShipperConfig(cfg)
	if err != nil {
		return nil, err
	}

	logger.Info().Str("server", srvCfg.Server).Msg("starting GRPC fake shipper server")
	lis, err := createListener(srvCfg.Server)
	if err != nil {
		return nil, err
	}
	if srvCfg.TLS == nil || srvCfg.TLS.Cert == "" || srvCfg.TLS.Key == "" {
		return nil, fmt.Errorf("ssl configuration missing")
	}
	cert, err := tls.X509KeyPair([]byte(srvCfg.TLS.Cert), []byte(srvCfg.TLS.Key))
	if err != nil {
		return nil, err
	}
	srv := grpc.NewServer(grpc.Creds(credentials.NewServerTLSFromCert(&cert)))
	i.srv = srv
	common.RegisterFakeEventProtocolServer(srv, i)
	i.wg.Go(func() error {
		return srv.Serve(lis)
	})

	logger.Trace().Msg("registering kill action for unit")
	unit.RegisterAction(&killAction{logger})
	logger.Debug().Str("state", client.UnitStateHealthy.String()).Str("message", healthyMsg).Msg("updating unit state")
	_ = unit.UpdateState(client.UnitStateHealthy, healthyMsg, nil)

	return i, nil
}

func (f *fakeShipperInput) Unit() *client.Unit {
	return f.unit
}

func (f *fakeShipperInput) Update(u *client.Unit) error {
	expected, _, config := u.Expected()
	if expected == client.UnitStateStopped {
		// agent is requesting this to stop
		f.logger.Debug().Str("state", client.UnitStateStopping.String()).Str("message", stoppingMsg).Msg("updating unit state")
		_ = u.UpdateState(client.UnitStateStopping, stoppingMsg, nil)
		go func() {
			if f.srv != nil {
				f.srv.Stop()
				f.wg.Wait()
				f.srv = nil
			}
			f.logger.Debug().Str("state", client.UnitStateStopped.String()).Str("message", stoppedMsg).Msg("updating unit state")
			_ = u.UpdateState(client.UnitStateStopped, stoppedMsg, nil)
		}()
		return nil
	}

	if config.Type == "" {
		return fmt.Errorf("unit missing config type")
	}
	if config.Type != fakeActionOutput {
		return fmt.Errorf("unit type changed with the same unit ID: %s", config.Type)
	}
	// nothing to really do
	return nil
}

func (f *fakeShipperInput) SendEvent(ctx context.Context, event *common.Event) (*common.EventResponse, error) {
	err := f.manager.received(ctx, event)
	if err != nil {
		return nil, err
	}
	return &common.EventResponse{}, nil
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
	_, logLevel, config := unit.Expected()
	if config.Type == "" {
		return nil, fmt.Errorf("unit config type empty")
	}
	if unit.Type() == client.UnitTypeOutput {
		switch config.Type {
		case fakeActionOutput:
			return newFakeActionOutputRuntime(logger, logLevel, unit, config)
		}
		return nil, fmt.Errorf("unknown output unit config type: %s", config.Type)
	} else if unit.Type() == client.UnitTypeInput {
		switch config.Type {
		case fakeShipper:
			return newFakeShipperInput(logger, logLevel, manager, unit, config)
		}
		return nil, fmt.Errorf("unknown input unit config type: %s", config.Type)
	}
	return nil, fmt.Errorf("unknown unit type: %+v", unit.Type())
}

func newUnitKey(unit *client.Unit) unitKey {
	return unitKey{
		unitType: unit.Type(),
		unitID:   unit.ID(),
	}
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
