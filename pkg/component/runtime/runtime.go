// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package runtime

import (
	"context"
	"errors"
	"sync"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/elastic/elastic-agent-client/v7/pkg/proto"
	"github.com/elastic/elastic-agent-libs/atomic"
	"github.com/elastic/elastic-agent/internal/pkg/runner"
	"github.com/elastic/elastic-agent/pkg/component"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

// componentRuntime manages runtime lifecycle operations for a component and stores its state.
type componentRuntime interface {
	// Run starts the runtime for the component.
	//
	// Called by Manager inside a goroutine. Run does not return until the passed in context is done. Run is always
	// called before any of the other methods in the interface and once the context is done none of those methods should
	// ever be called again.
	Run(ctx context.Context, comm Communicator) error
	// Watch returns the channel that sends component state.
	//
	// Channel should send a new state anytime a state for a unit or the whole component changes.
	Watch() <-chan ComponentState
	// Start starts the component.
	//
	// Must be non-blocking and never return an error unless the whole Elastic Agent needs to exit.
	Start() error
	// Update updates the currComp runtime with a new-revision for the component definition.
	//
	// Must be non-blocking and never return an error unless the whole Elastic Agent needs to exit.
	Update(comp component.Component) error
	// Stop stops the component.
	//
	// Must be non-blocking and never return an error unless the whole Elastic Agent needs to exit.
	//
	// Used to stop the running component. This is used when it will be restarted or upgraded. If the component
	// is being completely removed Teardown will be used instead.
	Stop() error
	// Teardown both stops and performs cleanup for the component.
	//
	// Must be non-blocking and never return an error unless the whole Elastic Agent needs to exit.
	//
	// Used to tell control the difference between stopping a component to restart it or upgrade it, versus
	// the component being completely removed.
	Teardown() error
}

// newComponentRuntime creates the proper runtime based on the input specification for the component.
func newComponentRuntime(
	comp component.Component,
	logger *logger.Logger,
	monitor MonitoringManager,
) (componentRuntime, error) {
	if comp.Err != nil {
		return newFailedRuntime(comp)
	}
	if comp.InputSpec != nil {
		if comp.InputSpec.Spec.Command != nil {
			return newCommandRuntime(comp, logger, monitor)
		}
		if comp.InputSpec.Spec.Service != nil {
			return newServiceRuntime(comp, logger)
		}
		return nil, errors.New("unknown component runtime")
	}
	if comp.ShipperSpec != nil {
		if comp.ShipperSpec.Spec.Command != nil {
			return newCommandRuntime(comp, logger, monitor)
		}
		return nil, errors.New("components for shippers can only support command runtime")
	}
	return nil, errors.New("component missing specification")
}

type componentRuntimeState struct {
	manager *Manager
	logger  *logger.Logger
	comm    *runtimeComm

	id         string
	currCompMx sync.RWMutex
	currComp   component.Component
	runtime    componentRuntime

	shuttingDown atomic.Bool

	latestMx    sync.RWMutex
	latestState ComponentState

	actionsMx sync.Mutex
	actions   map[string]func(*proto.ActionResponse)
}

func newComponentRuntimeState(m *Manager, logger *logger.Logger, monitor MonitoringManager, comp component.Component) (*componentRuntimeState, error) {
	comm, err := newRuntimeComm(logger, m.getListenAddr(), m.ca, m.agentInfo)
	if err != nil {
		return nil, err
	}
	runtime, err := newComponentRuntime(comp, logger, monitor)
	if err != nil {
		return nil, err
	}

	state := &componentRuntimeState{
		manager:  m,
		logger:   logger,
		comm:     comm,
		id:       comp.ID,
		currComp: comp,
		runtime:  runtime,
		latestState: ComponentState{
			State:   client.UnitStateStarting,
			Message: "Starting",
			Units:   nil,
		},
		actions: make(map[string]func(response *proto.ActionResponse)),
	}

	// Start the goroutine that spawns and monitors the component runtime.
	go state.runLoop()

	return state, nil
}

func (s *componentRuntimeState) runLoop() {
	// start the go-routine that operates the runtime for the component
	runtimeRunner := runner.Start(context.Background(), func(ctx context.Context) error {
		defer s.comm.destroy()
		_ = s.runtime.Run(ctx, s.comm)
		return nil
	})

	for {
		select {
		case <-runtimeRunner.Done():
			// Exit from the watcher loop only when the runner is done
			return
		case componentState := <-s.runtime.Watch():
			s.latestMx.Lock()
			s.latestState = componentState
			s.latestMx.Unlock()
			if s.manager.stateChanged(s, componentState) {
				runtimeRunner.Stop()
			}
		case ar := <-s.comm.actionsResponse:
			s.logger.Infof("got actionResponse in runLoop; id=%s diags=%d", ar.Id, len(ar.Diagnostic))
			s.actionsMx.Lock()
			s.logger.Infof("got mutex; got actionResponse in runLoop; id=%s diags=%d", ar.Id, len(ar.Diagnostic))
			callback, ok := s.actions[ar.Id]
			if ok {
				delete(s.actions, ar.Id)
			}
			s.actionsMx.Unlock()
			s.logger.Infof("unlocked mutex; got actionResponse in runLoop; id=%s diags=%d", ar.Id, len(ar.Diagnostic))
			if ok {
				s.logger.Infof("about to make callback; got actionResponse in runLoop; id=%s diags=%d", ar.Id, len(ar.Diagnostic))
				callback(ar)
				s.logger.Infof("made callback; got actionResponse in runLoop; id=%s diags=%d", ar.Id, len(ar.Diagnostic))
			}
		}
	}
}

func (s *componentRuntimeState) getCurrent() component.Component {
	s.currCompMx.RLock()
	defer s.currCompMx.RUnlock()
	return s.currComp
}

func (s *componentRuntimeState) setCurrent(current component.Component) {
	s.currCompMx.Lock()
	s.currComp = current
	s.currCompMx.Unlock()
}

func (s *componentRuntimeState) start() error {
	return s.runtime.Start()
}

func (s *componentRuntimeState) stop(teardown bool) error {
	s.shuttingDown.Store(true)
	if teardown {
		return s.runtime.Teardown()
	}
	return s.runtime.Stop()
}

func (s *componentRuntimeState) performAction(ctx context.Context, req *proto.ActionRequest) (*proto.ActionResponse, error) {
	ch := make(chan *proto.ActionResponse)
	callback := func(response *proto.ActionResponse) {
		ch <- response
	}

	s.logger.Infof("in performAction; locking actionsMx for req %s", req.Id)
	s.actionsMx.Lock()
	s.logger.Infof("in performAction; got actionsMx for req %s", req.Id)
	s.actions[req.Id] = callback
	s.actionsMx.Unlock()
	s.logger.Infof("in performAction; unlocked actionsMx for req %s", req.Id)

	select {
	case <-ctx.Done():
		s.logger.Infof("in performAction; got ctx.Done for actionsRequest  %s", req.Id)
		s.actionsMx.Lock()
		delete(s.actions, req.Id)
		s.actionsMx.Unlock()
		return nil, ctx.Err()
	case s.comm.actionsRequest <- req:
	}

	var resp *proto.ActionResponse

	select {
	case <-ctx.Done():
		s.logger.Infof("in performAction; got ctx.Done for resp  %s", req.Id)
		s.actionsMx.Lock()
		delete(s.actions, req.Id)
		s.actionsMx.Unlock()
		return nil, ctx.Err()
	case resp = <-ch:
	}

	return resp, nil
}
