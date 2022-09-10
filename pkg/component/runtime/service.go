// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package runtime

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/elastic/elastic-agent/pkg/component"
	"github.com/elastic/elastic-agent/pkg/core/logger"
	"github.com/kardianos/service"
)

type serviceAction int

const (
	checkServiceStatusInterval = 30 * time.Second // 30 seconds default for now, consistent with the command check-in interval
)

var (
	ErrOperationSpecUndefined = errors.New("operation spec undefined")
	ErrInvalidServiceSpec     = errors.New("invalid service spec")
)

type platformServiceFunc func(name string) (service.Service, error)
type executeServiceCommandFunc func(ctx context.Context, log *logger.Logger, binaryPath string, spec *component.ServiceOperationsCommandSpec) error

// ServiceRuntime provides the command runtime for running a component as a service.
type ServiceRuntime struct {
	current component.Component
	log     *logger.Logger

	ch       chan ComponentState
	actionCh chan actionMode
	compCh   chan component.Component
	statusCh chan service.Status

	state          ComponentState
	lastCheckin    time.Time
	missedCheckins int

	lastServiceStatus service.Status

	platformServiceImpl       platformServiceFunc
	executeServiceCommandImpl executeServiceCommandFunc
}

// NewServiceRuntime creates a new command runtime for the provided component.
func NewServiceRuntime(comp component.Component, logger *logger.Logger) (ComponentRuntime, error) {
	if comp.Spec.Spec.Service == nil {
		return nil, errors.New("must have service defined in specification")
	}

	return &ServiceRuntime{
		current:                   comp,
		log:                       logger,
		ch:                        make(chan ComponentState),
		actionCh:                  make(chan actionMode),
		compCh:                    make(chan component.Component),
		statusCh:                  make(chan service.Status),
		state:                     newComponentState(&comp),
		lastServiceStatus:         service.StatusUnknown,
		platformServiceImpl:       platformService,
		executeServiceCommandImpl: executeServiceCommand,
	}, nil
}

// check executes the service check command
func (s *ServiceRuntime) check(ctx context.Context) error {
	if s.current.Spec.Spec.Service.Operations.Check == nil {
		s.log.Errorf("missing check spec for %s service", s.current.Spec.BinaryName)
		return ErrOperationSpecUndefined
	}
	s.log.Debugf("check if the %s is installed", s.current.Spec.BinaryName)
	return s.executeServiceCommandImpl(ctx, s.log, s.current.Spec.BinaryPath, s.current.Spec.Spec.Service.Operations.Check)
}

// install executes the service install command
func (s *ServiceRuntime) install(ctx context.Context) error {
	if s.current.Spec.Spec.Service.Operations.Install == nil {
		s.log.Errorf("missing install spec for %s service", s.current.Spec.BinaryName)
		return ErrOperationSpecUndefined
	}
	s.log.Debugf("install %s service", s.current.Spec.BinaryName)
	return s.executeServiceCommandImpl(ctx, s.log, s.current.Spec.BinaryPath, s.current.Spec.Spec.Service.Operations.Install)
}

// uninstall executes the service uninstall command
func (s *ServiceRuntime) uninstall(ctx context.Context) error {
	if s.current.Spec.Spec.Service.Operations.Uninstall == nil {
		s.log.Errorf("missing uninstall spec for %s service", s.current.Spec.BinaryName)
		return ErrOperationSpecUndefined
	}
	s.log.Debugf("uninstall %s service", s.current.Spec.BinaryName)
	return s.executeServiceCommandImpl(ctx, s.log, s.current.Spec.BinaryPath, s.current.Spec.Spec.Service.Operations.Uninstall)
}

// Run starts the runtime for the component.
//
// Called by Manager inside a go-routine. Run should not return until the passed in context is done. Run is always
// called before any of the other methods in the interface and once the context is done none of those methods will
// ever be called again.
// The communicator is currently is not used with the service/daemon component.
// Perform the basic service status checks until we figure out the comms with the Endpoint.
func (s *ServiceRuntime) Run(ctx context.Context, comm Communicator) error {
	cli, err := s.platformService()
	if err != nil {
		return fmt.Errorf("failed create service client %s: %w", cli, err)
	}

	var (
		cis *connInfoServer
	)
	defer func() {
		if cis != nil {
			cis.stop()
		}
	}()

	checkinPeriod := s.current.Spec.Spec.Service.Timeouts.Checkin
	if checkinPeriod == 0 {
		checkinPeriod = checkServiceStatusInterval
	}

	t := time.NewTimer(checkinPeriod)
	t.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case as := <-s.actionCh:
			// Process action
			var err error
			switch as {
			case actionStart:
				err = s.start(ctx, cli)
			case actionStop:
				err = s.stop(cli)
			case actionTeardown:
				err = s.teardown(ctx, cli)
			}

			if err != nil {
				s.forceCompState(client.UnitStateFailed, err.Error())
				break
			}

			// Enable/disable periodic status checks
			switch as {
			case actionStart:
				// Kick off periodic service status checks
				t.Reset(checkinPeriod)
				if cis == nil {
					cis, err = newConnInfoServer(s.log, comm, s.current.Spec.Spec.Service.CPort)
					if err != nil {
						return fmt.Errorf("failed to start connection info service %s: %w", cli, err)
					}
				}
				s.lastCheckin = time.Time{}
				s.missedCheckins = 0
			case actionStop, actionTeardown:
				// Stop connection info service
				if cis != nil {
					cis.stop()
					cis = nil
				}

				// Stop period service status checks
				t.Stop()
			}

		case <-t.C:
			s.checkStatus(cli, checkinPeriod)
			t.Reset(checkinPeriod)
		case newComp := <-s.compCh:
			// TODO: switch to debug
			s.log.Infof("observed component update for %s service", cli)
			sendExpected := s.state.syncExpected(&newComp)
			changed := s.state.syncUnits(&newComp)
			if sendExpected || s.state.unsettled() {
				comm.CheckinExpected(s.state.toCheckinExpected())
			}
			if changed {
				s.sendObserved()
			}
		case checkin := <-comm.CheckinObserved():
			// TODO: switch to debug
			s.log.Infof("observed check-in for %s service", cli)
			sendExpected := false
			changed := false
			if s.state.State == client.UnitStateStarting {
				// first observation after start set component to healthy
				s.state.State = client.UnitStateHealthy
				s.state.Message = fmt.Sprintf("Healthy: communicating with %s service", cli)
				changed = true
			}
			if s.lastCheckin.IsZero() {
				// first check-in
				sendExpected = true
			}
			s.lastCheckin = time.Now().UTC()
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
	}
}

// checkStatus checks service status, called on timer
func (s *ServiceRuntime) checkStatus(cli service.Service, checkinPeriod time.Duration) {
	status, err := cli.Status()
	if err != nil {
		s.forceCompState(client.UnitStateFailed, fmt.Sprintf("Failed: service status check error: %v", err))
	}

	if s.lastServiceStatus != status {
		switch status {
		case service.StatusUnknown:
			s.forceCompState(client.UnitStateDegraded, fmt.Sprintf("Degraded: %s service status is unknown", cli))
		case service.StatusStopped:
			s.forceCompState(client.UnitStateStopped, fmt.Sprintf("Stopped: %s service", cli))
		}
	}

	if status == service.StatusRunning {
		now := time.Now().UTC()
		if s.lastCheckin.IsZero() {
			// never checked-in
			s.missedCheckins++
		} else if now.Sub(s.lastCheckin) > checkinPeriod {
			// missed check-in during required period
			s.missedCheckins++
		} else if now.Sub(s.lastCheckin) <= checkinPeriod {
			s.missedCheckins = 0
		}
		if s.missedCheckins == 0 {
			s.compState(client.UnitStateHealthy, cli)
		} else if s.missedCheckins > 0 && s.missedCheckins < maxCheckinMisses {
			s.compState(client.UnitStateDegraded, cli)
		} else if s.missedCheckins >= maxCheckinMisses {
			// something is wrong; the service should be checking in
			msg := fmt.Sprintf("Failed: %s service missed %d check-ins", cli, maxCheckinMisses)
			s.forceCompState(client.UnitStateFailed, msg)
		}
	}
	s.lastServiceStatus = status
}

// Watch returns the channel that sends component state.
//
// Channel should send a new state anytime a state for a unit or the whole component changes.
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

// start starts the service
func (s *ServiceRuntime) start(ctx context.Context, cli service.Service) error {
	s.forceCompState(client.UnitStateStarting, fmt.Sprintf("Starting: %s service", cli))

	// Call the check command of the service
	err := s.check(ctx)
	if err != nil {
		// Check failed, call the install command of the service
		s.log.Errorf("failed check %s service: %v, try install", cli, err)
		err = s.install(ctx)
		if err != nil {
			return fmt.Errorf("failed install %s service: %w", cli, err)
		}
	}

	// Check service status if it's already running
	status, err := cli.Status()
	if err != nil {
		return fmt.Errorf("failed checking %s service status: %w", cli, err)
	}

	// Service is running, set state and return
	if status == service.StatusRunning {
		s.forceCompState(client.UnitStateHealthy, fmt.Sprintf("Healthy: %s service is running", cli))
		return nil
	}

	// Start the service
	err = cli.Start()
	if err != nil {
		return fmt.Errorf("failed starting %s service: %w", cli, err)
	}

	// Check service status after attempting it to start
	status, err = cli.Status()
	if err != nil {
		return fmt.Errorf("failed checking %s service status: %w", cli, err)
	}

	if status == service.StatusRunning {
		s.forceCompState(client.UnitStateHealthy, fmt.Sprintf("Healthy: %s service is running", cli))
	}

	return nil
}

// stop stops the service
func (s *ServiceRuntime) stop(cli service.Service) error {
	s.forceCompState(client.UnitStateStopping, fmt.Sprintf("Stopping: %s service", cli))

	// Check service status if it's already stopped
	status, err := cli.Status()
	if err != nil {
		return fmt.Errorf("failed checking %s service status: %w", cli, err)
	}

	if status == service.StatusStopped {
		s.forceCompState(client.UnitStateStopped, fmt.Sprintf("Stopped: %s service", cli))
		return nil
	}

	// Stop service
	err = cli.Stop()
	if err != nil {
		return fmt.Errorf("failed stopping %s service: %w", cli, err)
	}

	// Check service status after attempting it to stop
	status, err = cli.Status()
	if err != nil {
		return fmt.Errorf("failed checking %s service status: %w", cli, err)
	}

	if status == service.StatusStopped {
		s.forceCompState(client.UnitStateStopped, fmt.Sprintf("Stopped: %s service", cli))
	}
	// TODO: what to do if not stopped?

	return nil
}

// teardown stops and uninstalls the service
func (s *ServiceRuntime) teardown(ctx context.Context, cli service.Service) error {
	err := s.stop(cli)
	if err != nil {
		s.log.Errorf("failed stop the service %s: %v, continue with uninstall", s.current.Spec.BinaryName, err)
	}
	return s.uninstall(ctx)
}

func (s *ServiceRuntime) compState(state client.UnitState, cli service.Service) {
	msg := "Unknown"
	if state == client.UnitStateHealthy {
		msg = fmt.Sprintf("Healthy: communicating with %s service", cli)
	} else if state == client.UnitStateDegraded {
		if s.missedCheckins == 1 {
			msg = fmt.Sprintf("Degraded: %s service missed 1 check-in", cli)
		} else {
			msg = fmt.Sprintf("Degraded: %s missed %d check-ins", cli, s.missedCheckins)
		}
	}
	if s.state.compState(state, msg) {
		s.sendObserved()
	}
}

// platformService returns the service.Service client that allows to manage the lifecycle of the service
func (s *ServiceRuntime) platformService() (service.Service, error) {
	if s.current.Spec.Spec.Service.Name == "" {
		return nil, fmt.Errorf("missing service name: %w", ErrInvalidServiceSpec)
	}

	return s.platformServiceImpl(s.current.Spec.Spec.Service.Name)
}

func platformService(name string) (service.Service, error) {
	svcConfig := &service.Config{
		Name: name,
	}

	cli, err := service.New(nil, svcConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to service %s: %w", svcConfig.Name, err)
	}
	return cli, nil
}
