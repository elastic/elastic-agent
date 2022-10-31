// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package runtime

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/kardianos/service"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/elastic/elastic-agent-client/v7/pkg/proto"
	"github.com/elastic/elastic-agent/pkg/component"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

const (
	defaultCheckServiceStatusInterval = 30 * time.Second // 30 seconds default for now, consistent with the command check-in interval
)

var (
	ErrOperationSpecUndefined = errors.New("operation spec undefined")
	ErrInvalidServiceSpec     = errors.New("invalid service spec")
)

type executeServiceCommandFunc func(ctx context.Context, log *logger.Logger, binaryPath string, spec *component.ServiceOperationsCommandSpec) error

// ServiceRuntime provides the command runtime for running a component as a service.
type ServiceRuntime struct {
	comp component.Component
	log  *logger.Logger

	ch       chan ComponentState
	actionCh chan actionMode
	compCh   chan component.Component
	statusCh chan service.Status

	state ComponentState

	executeServiceCommandImpl executeServiceCommandFunc
}

// NewServiceRuntime creates a new command runtime for the provided component.
func NewServiceRuntime(comp component.Component, logger *logger.Logger) (ComponentRuntime, error) {
	if comp.Spec.Spec.Service == nil {
		return nil, errors.New("must have service defined in specification")
	}

	state := newComponentState(&comp)

	s := &ServiceRuntime{
		comp:                      comp,
		log:                       logger.Named("service_runtime"),
		ch:                        make(chan ComponentState),
		actionCh:                  make(chan actionMode),
		compCh:                    make(chan component.Component),
		statusCh:                  make(chan service.Status),
		state:                     state,
		executeServiceCommandImpl: executeServiceCommand,
	}

	// Set initial state as STOPPED
	s.state.compState(client.UnitStateStopped, fmt.Sprintf("Stopped: %s service", s.name()))
	return s, nil
}

// Run starts the runtime for the component.
//
// Called by Manager inside a goroutine. Run does not return until the passed in context is done. Run is always
// called before any of the other methods in the interface and once the context is done none of those methods should
// ever be called again.
func (s *ServiceRuntime) Run(ctx context.Context, comm Communicator) (err error) {
	checkinTimer := time.NewTimer(s.checkinPeriod())
	defer checkinTimer.Stop()

	// Stop the check-ins timer initially
	checkinTimer.Stop()

	var (
		cis            *connInfoServer
		lastCheckin    time.Time
		missedCheckins int
	)

	cisStop := func() {
		if cis != nil {
			_ = cis.stop()
			cis = nil
		}
	}
	defer cisStop()

	for {
		var err error
		select {
		case <-ctx.Done():
			s.log.Debug("context is done. exiting.")
			return ctx.Err()
		case as := <-s.actionCh:
			switch as {
			case actionStart:
				// Initial state on start
				lastCheckin = time.Time{}
				missedCheckins = 0
				checkinTimer.Stop()
				cisStop()

				// Start connection info
				if cis == nil {
					cis, err = newConnInfoServer(s.log, comm, s.comp.Spec.Spec.Service.CPort)
					if err != nil {
						err = fmt.Errorf("failed to start connection info service %s: %w", s.name(), err)
						break
					}
				}

				// Start service
				err = s.start(ctx)
				if err != nil {
					cisStop()
					break
				}

				// Start check-in timer
				checkinTimer.Reset(s.checkinPeriod())
			case actionStop, actionTeardown:
				// Stop check-in timer
				s.log.Debugf("stop check-in timer for %s service", s.name())
				checkinTimer.Stop()

				// Stop connection info
				s.log.Debugf("stop connection info for %s service", s.name())
				cisStop()

				// Stop service
				s.stop(ctx, comm, lastCheckin, as == actionTeardown)
			}
			if err != nil {
				s.forceCompState(client.UnitStateFailed, err.Error())
			}
		case newComp := <-s.compCh:
			s.processNewComp(newComp, comm)
		case checkin := <-comm.CheckinObserved():
			s.processCheckin(checkin, comm, &lastCheckin)
		case <-checkinTimer.C:
			s.checkStatus(s.checkinPeriod(), &lastCheckin, &missedCheckins)
			checkinTimer.Reset(s.checkinPeriod())
		}
	}
}

func (s *ServiceRuntime) start(ctx context.Context) (err error) {
	name := s.name()

	// Set state to starting
	s.forceCompState(client.UnitStateStarting, fmt.Sprintf("Starting: %s service runtime", name))

	// Call the check command of the service
	s.log.Debugf("check if %s service is installed", name)
	err = s.check(ctx)
	s.log.Debugf("after check if %s service is installed, err: %v", name, err)
	if err != nil {
		// Check failed, call the install command of the service
		s.log.Debugf("failed check %s service: %v, try install", name, err)
		err = s.install(ctx)
		if err != nil {
			return fmt.Errorf("failed install %s service: %w", name, err)
		}
	}

	// The service should start on it's own, expecting check-ins
	return nil
}

func (s *ServiceRuntime) stop(ctx context.Context, comm Communicator, lastCheckin time.Time, teardown bool) {
	name := s.name()

	s.log.Debugf("stopping %s service runtime", name)

	checkedIn := !lastCheckin.IsZero()

	if teardown {
		// If checked in before, send STOPPING
		if s.isRunning() {
			// If never checked in await for the checkin with the timeout
			if !checkedIn {
				timeout := s.checkinPeriod()
				s.log.Debugf("%s service had never checked in, await for check-in for %v", name, timeout)
				checkedIn = s.awaitCheckin(ctx, comm, timeout)
			}

			// Received check in send STOPPING
			if checkedIn {
				s.log.Debugf("send stopping state to %s service", name)
				s.state.forceExpectedState(client.UnitStateStopping)
				comm.CheckinExpected(s.state.toCheckinExpected())
			} else {
				s.log.Debugf("%s service had never checked in, proceed to uninstall", name)
			}
		}

		s.log.Debug("uninstall %s service", name)
		err := s.uninstall(ctx)
		if err != nil {
			s.log.Errorf("failed %s service uninstall, err: %v", name, err)
		}
	}

	// Force component stopped state
	s.log.Debug("set %s service runtime to stopped state", name)
	s.forceCompState(client.UnitStateStopped, fmt.Sprintf("Stopped: %s service runtime", name))
}

// awaitCheckin awaits checkin with timeout.
func (s *ServiceRuntime) awaitCheckin(ctx context.Context, comm Communicator, timeout time.Duration) bool {
	name := s.name()
	t := time.NewTimer(timeout)
	defer t.Stop()

	for {
		select {
		case <-ctx.Done():
			// stop cancelled
			s.log.Debugf("stopping %s service, cancelled", name)
			return false
		case <-t.C:
			// stop timed out
			s.log.Debugf("stopping %s service, timed out", name)
			return false
		case <-comm.CheckinObserved():
			return true
		}
	}
}

func (s *ServiceRuntime) processNewComp(newComp component.Component, comm Communicator) {
	s.log.Debugf("observed component update for %s service", s.name())
	sendExpected := s.state.syncExpected(&newComp)
	changed := s.state.syncUnits(&newComp)
	if sendExpected || s.state.unsettled() {
		comm.CheckinExpected(s.state.toCheckinExpected())
	}
	if changed {
		s.sendObserved()
	}
}

func (s *ServiceRuntime) processCheckin(checkin *proto.CheckinObserved, comm Communicator, lastCheckin *time.Time) {
	name := s.name()

	s.log.Debugf("observed check-in for %s service: %v", name, checkin)
	sendExpected := false
	changed := false

	if s.state.State == client.UnitStateStarting {
		// first observation after start, set component to healthy
		s.state.State = client.UnitStateHealthy
		s.state.Message = fmt.Sprintf("Healthy: communicating with %s service", name)
		changed = true
	}

	if !s.isRunning() {
		return
	}

	if lastCheckin.IsZero() {
		// first check-in
		sendExpected = true
	}
	*lastCheckin = time.Now().UTC()
	if s.state.syncCheckin(checkin) {
		changed = true
	}
	if s.state.unsettled() {
		sendExpected = true
	}
	if sendExpected {
		comm.CheckinExpected(s.state.toCheckinExpected())
	}
	if changed {
		s.sendObserved()
	}
	if s.state.cleanupStopped() {
		s.sendObserved()
	}
}

// isRunning returns true is the service is running
func (s *ServiceRuntime) isRunning() bool {
	return s.state.State != client.UnitStateStopping &&
		s.state.State != client.UnitStateStopped
}

// checkStatus checks check-ins state, called on timer
func (s *ServiceRuntime) checkStatus(checkinPeriod time.Duration, lastCheckin *time.Time, missedCheckins *int) {
	if s.isRunning() {
		now := time.Now().UTC()
		if lastCheckin.IsZero() {
			// never checked-in
			*missedCheckins++
		} else if now.Sub(*lastCheckin) > checkinPeriod {
			// missed check-in during required period
			*missedCheckins++
		} else if now.Sub(*lastCheckin) <= checkinPeriod {
			*missedCheckins = 0
		}
		if *missedCheckins == 0 {
			s.compState(client.UnitStateHealthy, *missedCheckins)
		} else if *missedCheckins > 0 && *missedCheckins < maxCheckinMisses {
			s.compState(client.UnitStateDegraded, *missedCheckins)
		} else if *missedCheckins >= maxCheckinMisses {
			// something is wrong; the service should be checking in
			msg := fmt.Sprintf("Failed: %s service missed %d check-ins", s.name(), maxCheckinMisses)
			s.forceCompState(client.UnitStateFailed, msg)
		}
	}
}

func (s *ServiceRuntime) checkinPeriod() time.Duration {
	checkinPeriod := s.comp.Spec.Spec.Service.Timeouts.Checkin
	if checkinPeriod == 0 {
		checkinPeriod = defaultCheckServiceStatusInterval
	}
	return checkinPeriod
}

// Watch returns a channel to watch for component state changes.
//
// A new state is sent anytime the state for a unit or the whole component changes.
func (s *ServiceRuntime) Watch() <-chan ComponentState {
	return s.ch
}

// Start starts the service.
//
// Non-blocking and never returns an error.
func (s *ServiceRuntime) Start() error {
	s.actionCh <- actionStart
	return nil
}

// Update updates the currComp runtime with a new-revision for the component definition.
//
// Non-blocking and never returns an error.
func (s *ServiceRuntime) Update(comp component.Component) error {
	s.compCh <- comp
	return nil
}

// Stop stops the service.
//
// Non-blocking and never returns an error.
func (s *ServiceRuntime) Stop() error {
	s.actionCh <- actionStop
	return nil
}

// Teardown stop and uninstall the service.
//
// Non-blocking and never returns an error.
func (s *ServiceRuntime) Teardown() error {
	s.actionCh <- actionTeardown
	return nil
}

func (s *ServiceRuntime) forceCompState(state client.UnitState, msg string) {
	if s.state.forceState(state, msg) {
		s.sendObserved()
	}
}

func (s *ServiceRuntime) sendObserved() {
	s.ch <- s.state.Copy()
}

func (s *ServiceRuntime) compState(state client.UnitState, missedCheckins int) {
	name := s.name()
	msg := stateUnknownMessage
	if state == client.UnitStateHealthy {
		msg = fmt.Sprintf("Healthy: communicating with %s service", name)
	} else if state == client.UnitStateDegraded {
		if missedCheckins == 1 {
			msg = fmt.Sprintf("Degraded: %s service missed 1 check-in", name)
		} else {
			msg = fmt.Sprintf("Degraded: %s missed %d check-ins", name, missedCheckins)
		}
	}
	if s.state.compState(state, msg) {
		s.sendObserved()
	}
}

func (s *ServiceRuntime) name() string {
	return s.comp.Spec.Spec.Name
}

// check executes the service check command
func (s *ServiceRuntime) check(ctx context.Context) error {
	if s.comp.Spec.Spec.Service.Operations.Check == nil {
		s.log.Errorf("missing check spec for %s service", s.comp.Spec.BinaryName)
		return ErrOperationSpecUndefined
	}
	s.log.Debugf("check if the %s is installed", s.comp.Spec.BinaryName)
	return s.executeServiceCommandImpl(ctx, s.log, s.comp.Spec.BinaryPath, s.comp.Spec.Spec.Service.Operations.Check)
}

// install executes the service install command
func (s *ServiceRuntime) install(ctx context.Context) error {
	if s.comp.Spec.Spec.Service.Operations.Install == nil {
		s.log.Errorf("missing install spec for %s service", s.comp.Spec.BinaryName)
		return ErrOperationSpecUndefined
	}
	s.log.Debugf("install %s service", s.comp.Spec.BinaryName)
	return s.executeServiceCommandImpl(ctx, s.log, s.comp.Spec.BinaryPath, s.comp.Spec.Spec.Service.Operations.Install)
}

// uninstall executes the service uninstall command
func (s *ServiceRuntime) uninstall(ctx context.Context) error {
	return uninstallService(ctx, s.log, s.comp, s.executeServiceCommandImpl)
}

// UninstallService uninstalls the service
func UninstallService(ctx context.Context, log *logger.Logger, comp component.Component) error {
	return uninstallService(ctx, log, comp, executeServiceCommand)
}

func uninstallService(ctx context.Context, log *logger.Logger, comp component.Component, executeServiceCommandImpl executeServiceCommandFunc) error {
	if comp.Spec.Spec.Service.Operations.Uninstall == nil {
		log.Errorf("missing uninstall spec for %s service", comp.Spec.BinaryName)
		return ErrOperationSpecUndefined
	}
	log.Debugf("uninstall %s service", comp.Spec.BinaryName)
	return executeServiceCommandImpl(ctx, log, comp.Spec.BinaryPath, comp.Spec.Spec.Service.Operations.Uninstall)
}
