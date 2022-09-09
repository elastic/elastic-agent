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
	"github.com/elastic/elastic-agent/pkg/component"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

// ComponentRuntime manages runtime lifecycle operations for a component and stores its state.
type ComponentRuntime interface {
	// Run starts the runtime for the component.
	//
	// Called by Manager inside a go-routine. Run should not return until the passed in context is done. Run is always
	// called before any of the other methods in the interface and once the context is done none of those methods will
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

// NewComponentRuntime creates the proper runtime based on the input specification for the component.
func NewComponentRuntime(comp component.Component, monitor MonitoringManager) (ComponentRuntime, error) {
	if comp.Err != nil {
		return NewFailedRuntime(comp)
	} else if comp.Spec.Spec.Command != nil {
		return NewCommandRuntime(comp, monitor)
	} else if comp.Spec.Spec.Service != nil {
		return nil, errors.New("service component runtime not implemented")
	}
	return nil, errors.New("unknown component runtime")
}

type componentRuntimeState struct {
	manager *Manager
	logger  *logger.Logger
	comm    *runtimeComm

	currComp component.Component
	runtime  ComponentRuntime

	shuttingDown atomic.Bool

	latestMx    sync.RWMutex
	latestState ComponentState

	watchChan      chan bool
	watchCanceller context.CancelFunc

	runChan      chan bool
	runCanceller context.CancelFunc

	actionsMx sync.Mutex
	actions   map[string]func(*proto.ActionResponse)
}

func newComponentRuntimeState(m *Manager, logger *logger.Logger, monitor MonitoringManager, comp component.Component) (*componentRuntimeState, error) {
	comm, err := newRuntimeComm(logger, m.getListenAddr(), m.ca, m.agentInfo)
	if err != nil {
		return nil, err
	}
	runtime, err := NewComponentRuntime(comp, monitor)
	if err != nil {
		return nil, err
	}

	watchChan := make(chan bool)
	runChan := make(chan bool)
	state := &componentRuntimeState{
		manager:  m,
		logger:   logger,
		comm:     comm,
		currComp: comp,
		runtime:  runtime,
		latestState: ComponentState{
			State:   client.UnitStateStarting,
			Message: "Starting",
			Units:   nil,
		},
		watchChan: watchChan,
		runChan:   runChan,
		actions:   make(map[string]func(response *proto.ActionResponse)),
	}

	// start the go-routine that watches for updates from the component
	watchCtx, watchCanceller := context.WithCancel(context.Background())
	state.watchCanceller = watchCanceller
	go func() {
		defer close(watchChan)
		for {
			select {
			case <-watchCtx.Done():
				return
			case s := <-runtime.Watch():
				state.latestMx.Lock()
				state.latestState = s
				state.latestMx.Unlock()
				state.manager.stateChanged(state, s)
			case ar := <-comm.actionsResponse:
				state.actionsMx.Lock()
				callback, ok := state.actions[ar.Id]
				if ok {
					delete(state.actions, ar.Id)
				}
				state.actionsMx.Unlock()
				if ok {
					callback(ar)
				}
			}
		}
	}()

	// start the go-routine that operates the runtime for the component
	runCtx, runCanceller := context.WithCancel(context.Background())
	state.runCanceller = runCanceller
	go func() {
		defer close(runChan)
		defer comm.destroy()
		_ = runtime.Run(runCtx, comm)
	}()

	return state, nil
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

func (s *componentRuntimeState) destroy() {
	if s.runCanceller != nil {
		s.runCanceller()
		s.runCanceller = nil
		<-s.runChan
	}
	if s.watchCanceller != nil {
		s.watchCanceller()
		s.watchCanceller = nil
		<-s.watchChan
	}
}

func (s *componentRuntimeState) performAction(ctx context.Context, req *proto.ActionRequest) (*proto.ActionResponse, error) {
	ch := make(chan *proto.ActionResponse)
	callback := func(response *proto.ActionResponse) {
		ch <- response
	}

	s.actionsMx.Lock()
	s.actions[req.Id] = callback
	s.actionsMx.Unlock()

	select {
	case <-ctx.Done():
		s.actionsMx.Lock()
		delete(s.actions, req.Id)
		s.actionsMx.Unlock()
		return nil, ctx.Err()
	case s.comm.actionsRequest <- req:
	}

	var resp *proto.ActionResponse

	select {
	case <-ctx.Done():
		s.actionsMx.Lock()
		delete(s.actions, req.Id)
		s.actionsMx.Unlock()
		return nil, ctx.Err()
	case resp = <-ch:
	}

	return resp, nil
}
