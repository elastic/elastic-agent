// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package runtime

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"time"

	"github.com/kardianos/service"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/elastic/elastic-agent-client/v7/pkg/proto"
	"github.com/elastic/elastic-agent/pkg/component"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

const (
	defaultCheckServiceStatusInterval = 30 * time.Second // 30 seconds default for now, consistent with the command check-in interval
	defaultServiceStopTimeout         = 3 * time.Minute  // 3 minutes default wait for the service stop
)

var (
	ErrOperationSpecUndefined = errors.New("operation spec undefined")
	ErrInvalidServiceSpec     = errors.New("invalid service spec")
	ErrFailedServiceStop      = errors.New("failed service stop")
)

type runtimeStatus byte

const (
	runtimeStatusStopped runtimeStatus = iota
	runtimeStatusStarting
	runtimeStatusRunning
	runtimeStatusStopping
)

func (s runtimeStatus) String() string {
	return []string{"stopped", "starting", "running", "stopping"}[s]
}

type platformServiceFunc func(name string) (service.Service, error)
type executeServiceCommandFunc func(ctx context.Context, log *logger.Logger, binaryPath string, spec *component.ServiceOperationsCommandSpec) error

// ServiceRuntime provides the command runtime for running a component as a service.
type ServiceRuntime struct {
	runtimeStatus runtimeStatus
	comp          component.Component
	log           *logger.Logger

	ch       chan ComponentState
	actionCh chan actionMode
	compCh   chan component.Component
	statusCh chan service.Status

	state          ComponentState
	lastCheckin    time.Time
	missedCheckins int

	platformServiceImpl       platformServiceFunc
	executeServiceCommandImpl executeServiceCommandFunc
}

// NewServiceRuntime creates a new command runtime for the provided component.
func NewServiceRuntime(comp component.Component, logger *logger.Logger) (ComponentRuntime, error) {
	if comp.Spec.Spec.Service == nil {
		return nil, errors.New("must have service defined in specification")
	}

	return &ServiceRuntime{
		runtimeStatus:             runtimeStatusStopped,
		comp:                      comp,
		log:                       logger.Named("service_runtime"),
		ch:                        make(chan ComponentState),
		actionCh:                  make(chan actionMode),
		compCh:                    make(chan component.Component),
		statusCh:                  make(chan service.Status),
		state:                     newComponentState(&comp),
		platformServiceImpl:       platformService,
		executeServiceCommandImpl: executeServiceCommand,
	}, nil
}

// Run starts the runtime for the component.
//
// Called by Manager inside a goroutine. Run should not return until the passed in context is done. Run should always
// be called before any of the other methods in the interface and once the context is done none of those methods should
// ever be called again.
func (s *ServiceRuntime) Run(ctx context.Context, comm Communicator) (err error) {
	cli, err := s.platformService()
	if err != nil {
		return fmt.Errorf("failed create service client %s: %w", cli, err)
	}

	checkinTimer := time.NewTimer(s.getCheckinPeriod())
	defer checkinTimer.Stop()

	// Stop the check-ins timer initially
	checkinTimer.Stop()

	var (
		cis *connInfoServer
	)
	defer func() {
		if cis != nil {
			_ = cis.stop()
		}
	}()

	for {
		select {
		case <-ctx.Done():
			s.log.Debug("context is done. exiting.")
			return ctx.Err()
		case as := <-s.actionCh:
			var err error
			switch as {
			case actionStart:
				if cis == nil {
					cis, err = newConnInfoServer(s.log, comm, s.comp.Spec.Spec.Service.CPort)
					if err != nil {
						return fmt.Errorf("failed to start connection info service %s: %w", cli, err)
					}
				}
				err = s.start(ctx, cli)
				if err == nil {
					// Start check-in timer
					checkinTimer.Reset(s.getCheckinPeriod())
				}
			case actionStop, actionTeardown:
				err = s.stop(ctx, comm, cli)
				if err == nil {
					// Stop connection info service
					if cis != nil {
						_ = cis.stop()
						cis = nil
					}
					// Stop check-in timer
					if !checkinTimer.Stop() {
						<-checkinTimer.C
					}
				}
				if as == actionTeardown {
					err = s.uninstall(ctx)
				}
			}
			if err != nil {
				s.forceCompState(client.UnitStateFailed, err.Error())
			}
		case newComp := <-s.compCh:
			s.processNewComp(newComp, comm, cli)
		case checkin := <-comm.CheckinObserved():
			s.processCheckin(checkin, comm, cli)
		case <-checkinTimer.C:
			s.checkStatus(cli, s.getCheckinPeriod())
		}
	}
}

func (s *ServiceRuntime) processNewComp(newComp component.Component, comm Communicator, cli service.Service) {
	s.log.Debugf("observed component update for %s service", cli)
	sendExpected := s.state.syncExpected(&newComp)
	changed := s.state.syncUnits(&newComp)
	if sendExpected || s.state.unsettled() {
		comm.CheckinExpected(s.state.toCheckinExpected())
	}
	if changed {
		s.sendObserved()
	}
}

func (s *ServiceRuntime) processCheckin(checkin *proto.CheckinObserved, comm Communicator, cli service.Service) {
	s.log.Infof("observed check-in for %s service", cli)
	sendExpected := false
	changed := false
	if s.state.State == client.UnitStateStarting {
		// first observation after start, set component to healthy
		s.state.State = client.UnitStateHealthy
		s.state.Message = fmt.Sprintf("Healthy: communicating with %s service", cli)
		changed = true
		s.runtimeStatus = runtimeStatusRunning
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

// checkStatus checks check-ins state, called on timer
func (s *ServiceRuntime) checkStatus(cli service.Service, checkinPeriod time.Duration) {
	if s.runtimeStatus == runtimeStatusRunning {
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
}

func (s *ServiceRuntime) start(ctx context.Context, cli service.Service) (err error) {
	if s.runtimeStatus != runtimeStatusStopped {
		s.log.Debugf("%s service can't be started, already %s", cli, s.runtimeStatus)
		return nil
	}

	defer func() {
		if err != nil {
			s.runtimeStatus = runtimeStatusStopped
		}
	}()

	s.log.Debugf("start %s service", cli)
	s.runtimeStatus = runtimeStatusStarting

	// Reset tracked check-ins
	s.lastCheckin = time.Time{}
	s.missedCheckins = 0

	// Set state to starting
	s.forceCompState(client.UnitStateStarting, fmt.Sprintf("Starting: %s service", cli))

	// Call the check command of the service
	err = s.check(ctx)
	if err != nil {
		// Check failed, call the install command of the service
		s.log.Debugf("failed check %s service: %v, try install", cli, err)
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
		s.runtimeStatus = runtimeStatusRunning
		s.forceCompState(client.UnitStateHealthy, fmt.Sprintf("Healthy: %s service is running", cli))
		return nil
	}

	// Start the service
	err = cli.Start()
	if err != nil {
		return fmt.Errorf("failed starting %s service: %w", cli, err)
	}

	// The service is expected to check-in after starting
	// That's where the service status will be set

	return nil
}

func (s *ServiceRuntime) stop(ctx context.Context, comm Communicator, cli service.Service) (err error) {
	if s.runtimeStatus != runtimeStatusRunning {
		s.log.Debug("%s service can't be started, already %s", cli, s.runtimeStatus)
		return nil
	}

	// Reset the service runtime status to the previous status if the stop failed
	runtimeStatus := s.runtimeStatus
	defer func() {
		if err != nil {
			s.runtimeStatus = runtimeStatus
		}
	}()

	s.log.Debug("stopping %s service", cli)
	s.runtimeStatus = runtimeStatusStopping

	// Send stopping state to the service
	s.forceCompState(client.UnitStateStopping, fmt.Sprintf("Stopping: %s service", cli))
	comm.CheckinExpected(s.state.toCheckinExpected())

	// Awating the service to check-in with stopped state
	t := time.NewTimer(s.getStopTimeout())
	defer t.Stop()

CHECKLOOP:
	for {
		select {
		case <-ctx.Done():
			// stop cancelled
			s.log.Debug("stopping %s service, cancelled", cli)
			return ctx.Err()
		case <-t.C:
			// stop timed out
			s.log.Debug("stopping %s service, timed out", cli)
			break CHECKLOOP
		case checkin := <-comm.CheckinObserved():
			s.processCheckin(checkin, comm, cli)
		}
	}

	// Return if service is stopped
	if s.state.State == client.UnitStateStopped {
		s.runtimeStatus = runtimeStatusStopped
		return nil
	}

	// Attempt to stop the service on non-windows platform
	if runtime.GOOS != "windows" {
		err = cli.Stop()
		if err != nil {
			return err
		}
	}

	// Monitor the service status with the platform services management
	name := cli.String()
	sw, err := newServiceWatcher(name)
	if err != nil {
		return fmt.Errorf("failed to create the %s service watcher, err: %w", name, err)
	}

	// Run service watcher.
	ctx, cn := context.WithCancel(ctx)
	defer cn()
	go func() {
		sw.run(ctx)
	}()

	var (
		lastStatus service.Status
		werr       error
	)

LOOP:
	for r := range sw.status() {
		if r.Err != nil {
			werr = r.Err
			// If service watcher returned the error, log the error and exit the loop
			s.log.Errorf("%s service watcher returned err: %v", name, werr)
			break LOOP
		} else {
			lastStatus = r.Status
			switch lastStatus {
			case service.StatusUnknown:
				s.log.Debugf("%s service watcher status: Unknown", name)
			case service.StatusRunning:
				s.log.Debugf("%s service watcher status: Running", name)
			case service.StatusStopped:
				s.log.Debugf("%s service watcher status: Stopped", name)
				break LOOP
			}
		}
	}

	// If service is stopped or uninstalled, set the runtime state into stopped
	if lastStatus == service.StatusStopped || errors.Is(werr, service.ErrNotInstalled) {
		s.runtimeStatus = runtimeStatusStopped
		s.forceCompState(client.UnitStateStopped, fmt.Sprintf("Stopped: %s service", cli))
	} else {
		err = ErrFailedServiceStop
		if werr != nil {
			err = fmt.Errorf("%s: %w", err, werr)
		}
		s.forceCompState(client.UnitStateFailed, fmt.Sprintf("Failed: while stopping %s service: %v", cli, err))
	}

	return err
}

func (s *ServiceRuntime) getCheckinPeriod() time.Duration {
	checkinPeriod := s.comp.Spec.Spec.Service.Timeouts.Checkin
	if checkinPeriod == 0 {
		checkinPeriod = defaultCheckServiceStatusInterval
	}
	return checkinPeriod
}

func (s *ServiceRuntime) getStopTimeout() time.Duration {
	stopTimeout := s.comp.Spec.Spec.Service.Timeouts.Stop
	if stopTimeout == 0 {
		stopTimeout = defaultServiceStopTimeout
	}
	return stopTimeout
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

func (s *ServiceRuntime) compState(state client.UnitState, cli service.Service) {
	msg := stateUnknownMessage
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
	name := s.comp.Spec.Spec.Service.Name
	if name == "" {
		return nil, fmt.Errorf("missing service name: %w", ErrInvalidServiceSpec)
	}

	return s.platformServiceImpl(name)
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
	if s.comp.Spec.Spec.Service.Operations.Uninstall == nil {
		s.log.Errorf("missing uninstall spec for %s service", s.comp.Spec.BinaryName)
		return ErrOperationSpecUndefined
	}
	s.log.Debugf("uninstall %s service", s.comp.Spec.BinaryName)
	return s.executeServiceCommandImpl(ctx, s.log, s.comp.Spec.BinaryPath, s.comp.Spec.Spec.Service.Operations.Uninstall)
}
