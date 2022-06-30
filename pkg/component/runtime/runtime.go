package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/elastic/elastic-agent-client/v7/pkg/proto"
	"github.com/elastic/elastic-agent-libs/atomic"
	"github.com/elastic/elastic-agent/pkg/component"
	"github.com/elastic/elastic-agent/pkg/core/logger"
	"sync"
)

// ComponentUnitState is the state for a unit running in a component.
type ComponentUnitState struct {
	State   client.UnitState
	Message string
	Payload map[string]interface{}

	// internal
	configStateIdx uint64
	config         map[string]interface{}
	payloadStr     string
}

// ComponentUnitKey is a composite key to identify a unit by its type and ID.
type ComponentUnitKey struct {
	UnitType client.UnitType
	UnitID   string
}

// ComponentState is the overall state of the component.
type ComponentState struct {
	State   client.UnitState
	Message string

	Units map[ComponentUnitKey]ComponentUnitState
}

func newComponentState(comp *component.Component, initState client.UnitState, initMessage string, initCfgIdx uint64) (s ComponentState) {
	s.Units = make(map[ComponentUnitKey]ComponentUnitState)
	s.syncComponent(comp, initState, initMessage, initCfgIdx)
	return s
}

// Copy returns a copy of the structure.
func (s *ComponentState) Copy() (c ComponentState) {
	c = *s
	c.Units = make(map[ComponentUnitKey]ComponentUnitState)
	for k, v := range s.Units {
		c.Units[k] = v
	}
	return c
}

func (s *ComponentState) syncComponent(comp *component.Component, initState client.UnitState, initMessage string, initCfgIdx uint64) {
	s.State = initState
	s.Message = initMessage
	touched := make(map[ComponentUnitKey]bool)
	for _, unit := range comp.Units {
		key := ComponentUnitKey{
			UnitType: unit.Type,
			UnitID:   unit.ID,
		}

		touched[key] = true
		existing, ok := s.Units[key]
		existing.State = initState
		existing.Message = initMessage
		existing.Payload = nil
		existing.config = unit.Config
		if ok {
			existing.configStateIdx += 1
		} else {
			existing.configStateIdx = initCfgIdx
		}
		s.Units[key] = existing
	}
	for key, unit := range s.Units {
		_, ok := touched[key]
		if !ok {
			if unit.State != client.UnitStateStopped {
				unit.State = client.UnitStateStopped
				unit.Message = "Stopped"

				// unit is a copy and must be set back into the map
				s.Units[key] = unit
			}
		}
	}
}

func (s *ComponentState) syncCheckin(checkin *proto.CheckinObserved) bool {
	changed := false
	touched := make(map[ComponentUnitKey]bool)
	for _, unit := range checkin.Units {
		key := ComponentUnitKey{
			UnitType: client.UnitType(unit.Type),
			UnitID:   unit.Id,
		}

		var payloadStr string
		var payload map[string]interface{}
		if unit.Payload != nil {
			payloadStr = string(unit.Payload)
			// err is ignored (must be valid JSON for Agent to use it)
			_ = json.Unmarshal(unit.Payload, &payload)
		}

		touched[key] = true
		existing, ok := s.Units[key]
		if !ok {
			changed = true
			existing = ComponentUnitState{
				State:          client.UnitState(unit.State),
				Message:        unit.Message,
				Payload:        payload,
				configStateIdx: unit.ConfigStateIdx,
				payloadStr:     payloadStr,
			}
		} else {
			existing.configStateIdx = unit.ConfigStateIdx
			if existing.State != client.UnitState(unit.State) || existing.Message != unit.Message || existing.payloadStr != payloadStr {
				changed = true
				existing.State = client.UnitState(unit.State)
				existing.Message = unit.Message
				existing.Payload = payload
				existing.payloadStr = payloadStr
			}
		}
		s.Units[key] = existing
	}
	for key, unit := range s.Units {
		_, ok := touched[key]
		if !ok {
			unit.configStateIdx = 0
			if unit.State != client.UnitStateStarting {
				state := client.UnitStateFailed
				msg := "Failed: not reported in check-in"
				payloadStr := ""
				if unit.State != state || unit.Message != msg || unit.payloadStr != payloadStr {
					changed = true
					unit.State = state
					unit.Message = msg
					unit.Payload = nil
					unit.payloadStr = payloadStr

					// unit is a copy and must be set back into the map
					s.Units[key] = unit
				}
			}
		}
	}
	return changed
}

// ComponentRuntime manages runtime lifecycle operations for a component and stores its state.
type ComponentRuntime interface {
	// Run starts the runtime for the component.
	//
	// Called by Manager inside a go-routine. Run should not return until the passed in context is done. Run is always
	// called before any of the other methods in the interface and once the context is done none of those methods will
	// ever be called again.
	Run(ctx context.Context, comm Communicator)
	// Watch returns the channel that sends component state.
	//
	// Channel should send a new state anytime a state for a unit or the whole component changes.
	Watch() <-chan ComponentState
	// Start starts the component.
	//
	// Must be non-blocking and never return an error unless the whole Elastic Agent needs to exit.
	Start() error
	// Update updates the current runtime with a new-revision for the component definition.
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
func NewComponentRuntime(comp component.Component) (ComponentRuntime, error) {
	if comp.Err != nil {
		return NewFailedRuntime(comp)
	} else if comp.Spec.Spec.Command != nil {
		return NewCommandRuntime(comp)
	} else if comp.Spec.Spec.Service != nil {
		return nil, errors.New("service component runtime not implemented")
	}
	return nil, errors.New("unknown component runtime")
}

type componentRuntimeState struct {
	manager *Manager
	logger  *logger.Logger
	comm    *runtimeComm

	current component.Component
	runtime ComponentRuntime

	shuttingDown atomic.Bool

	latestMx sync.RWMutex
	latest   ComponentState

	watchChan      chan bool
	watchCanceller context.CancelFunc

	runChan      chan bool
	runCanceller context.CancelFunc

	actionsMx sync.Mutex
	actions   map[string]func(*proto.ActionResponse)
}

func newComponentRuntimeState(m *Manager, logger *logger.Logger, comp component.Component) (*componentRuntimeState, error) {
	comm, err := newRuntimeComm(logger, m.getListenAddr(), m.ca)
	if err != nil {
		return nil, err
	}
	runtime, err := NewComponentRuntime(comp)
	if err != nil {
		return nil, err
	}

	watchChan := make(chan bool)
	runChan := make(chan bool)
	state := &componentRuntimeState{
		manager: m,
		logger:  logger,
		comm:    comm,
		current: comp,
		runtime: runtime,
		latest: ComponentState{
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
				state.latest = s
				state.latestMx.Unlock()
				state.manager.stateChanged(state, s)
			case ar := <-comm.actionsResponse:
				state.actionsMx.Lock()
				callback, ok := state.actions[ar.Id]
				if ok {
					delete(state.actions, ar.Id)
				}
				state.actionsMx.Unlock()
				callback(ar)
			}
		}
	}()

	// start the go-routine that operates the runtime for the component
	runCtx, runCanceller := context.WithCancel(context.Background())
	state.runCanceller = runCanceller
	go func() {
		defer close(runChan)
		defer comm.destroy()
		runtime.Run(runCtx, comm)
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
	} else {
		return s.runtime.Stop()
	}
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
