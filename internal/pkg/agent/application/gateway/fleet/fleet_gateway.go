// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package fleet

import (
	"context"
	"fmt"
	"time"

	eaclient "github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/coordinator"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/dispatcher"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/gateway"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
	agentclient "github.com/elastic/elastic-agent/internal/pkg/agent/control/client"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/internal/pkg/core/backoff"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi/acker"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi/client"
	"github.com/elastic/elastic-agent/internal/pkg/scheduler"
	"github.com/elastic/elastic-agent/pkg/component/runtime"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

// Max number of times an invalid API Key is checked
const maxUnauthCounter int = 6

// Const for decraded state or linter complains
const degraded = "degraded"

// Default Configuration for the Fleet Gateway.
var defaultGatewaySettings = &fleetGatewaySettings{
	Duration: 1 * time.Second,        // time between successful calls
	Jitter:   500 * time.Millisecond, // used as a jitter for duration
	Backoff: backoffSettings{ // time after a failed call
		Init: 60 * time.Second,
		Max:  10 * time.Minute,
	},
}

type fleetGatewaySettings struct {
	Duration time.Duration   `config:"checkin_frequency"`
	Jitter   time.Duration   `config:"jitter"`
	Backoff  backoffSettings `config:"backoff"`
}

type backoffSettings struct {
	Init time.Duration `config:"init"`
	Max  time.Duration `config:"max"`
}

type agentInfo interface {
	AgentID() string
}

type stateStore interface {
	Add(fleetapi.Action)
	AckToken() string
	SetAckToken(ackToken string)
	Save() error
	Actions() []fleetapi.Action
}

type fleetGateway struct {
	log           *logger.Logger
	dispatcher    dispatcher.Dispatcher
	client        client.Sender
	scheduler     scheduler.Scheduler
	settings      *fleetGatewaySettings
	agentInfo     agentInfo
	acker         acker.Acker
	unauthCounter int
	stateFetcher  coordinator.StateFetcher
	stateStore    stateStore
	errCh         chan error
}

// New creates a new fleet gateway
func New(
	log *logger.Logger,
	agentInfo agentInfo,
	client client.Sender,
	d dispatcher.Dispatcher,
	acker acker.Acker,
	stateFetcher coordinator.StateFetcher,
	stateStore stateStore,
) (gateway.FleetGateway, error) {

	scheduler := scheduler.NewPeriodicJitter(defaultGatewaySettings.Duration, defaultGatewaySettings.Jitter)
	return newFleetGatewayWithScheduler(
		log,
		defaultGatewaySettings,
		agentInfo,
		client,
		d,
		scheduler,
		acker,
		stateFetcher,
		stateStore,
	)
}

func newFleetGatewayWithScheduler(
	log *logger.Logger,
	settings *fleetGatewaySettings,
	agentInfo agentInfo,
	client client.Sender,
	d dispatcher.Dispatcher,
	scheduler scheduler.Scheduler,
	acker acker.Acker,
	stateFetcher coordinator.StateFetcher,
	stateStore stateStore,
) (gateway.FleetGateway, error) {
	return &fleetGateway{
		log:          log,
		dispatcher:   d,
		client:       client,
		settings:     settings,
		agentInfo:    agentInfo,
		scheduler:    scheduler,
		acker:        acker,
		stateFetcher: stateFetcher,
		stateStore:   stateStore,
		errCh:        make(chan error),
	}, nil
}

func (f *fleetGateway) Run(ctx context.Context) error {
	// Backoff implementation doesn't support the use of a context [cancellation] as the shutdown mechanism.
	// So we keep a done channel that will be closed when the current context is shutdown.
	done := make(chan struct{})
	backoff := backoff.NewEqualJitterBackoff(
		done,
		f.settings.Backoff.Init,
		f.settings.Backoff.Max,
	)
	go func() {
		<-ctx.Done()
		close(done)
	}()

	f.log.Info("Fleet gateway started")
	for {
		select {
		case <-ctx.Done():
			f.scheduler.Stop()
			f.log.Info("Fleet gateway stopped")
			return ctx.Err()
		case <-f.scheduler.WaitTick():
			f.log.Debug("FleetGateway calling Checkin API")

			// Execute the checkin call and for any errors returned by the fleet-server API
			// the function will retry to communicate with fleet-server with an exponential delay and some
			// jitter to help better distribute the load from a fleet of agents.
			resp, err := f.doExecute(ctx, backoff)
			if err != nil {
				continue
			}

			actions := make([]fleetapi.Action, len(resp.Actions))
			copy(actions, resp.Actions)

			// Persist state
			hadErr := false
			if err := f.dispatcher.Dispatch(context.Background(), f.acker, actions...); err != nil {
				err = fmt.Errorf("failed to dispatch actions, error: %w", err)
				f.log.Error(err)
				f.errCh <- err
				hadErr = true
			}

			f.log.Debugf("FleetGateway is sleeping, next update in %s", f.settings.Duration)
			if !hadErr {
				f.errCh <- nil
			}
		}
	}
}

// Errors returns the channel to watch for reported errors.
func (f *fleetGateway) Errors() <-chan error {
	return f.errCh
}

func (f *fleetGateway) doExecute(ctx context.Context, bo backoff.Backoff) (*fleetapi.CheckinResponse, error) {
	bo.Reset()

	// Guard if the context is stopped by a out of bound call,
	// this mean we are rebooting to change the log level or the system is shutting us down.
	for ctx.Err() == nil {
		f.log.Debugf("Checking started")
		resp, err := f.execute(ctx)
		if err != nil {
			f.log.Errorf("Could not communicate with fleet-server Checking API will retry, error: %s", err)
			if !bo.Wait() {
				// Something bad has happened and we log it and we should update our current state.
				err := errors.New(
					"execute retry loop was stopped",
					errors.TypeNetwork,
					errors.M(errors.MetaKeyURI, f.client.URI()),
				)

				f.log.Error(err)
				f.errCh <- err
				return nil, err
			}
			continue
		}
		// Request was successful, return the collected actions.
		return resp, nil
	}

	// This mean that the next loop was cancelled because of the context, we should return the error
	// but we should not log it, because we are in the process of shutting down.
	return nil, ctx.Err()
}

func (f *fleetGateway) convertToCheckinComponents(components []runtime.ComponentComponentState) []fleetapi.CheckinComponent {
	if components == nil {
		return nil
	}
	stateString := func(s eaclient.UnitState) string {
		switch s {
		case eaclient.UnitStateStarting:
			return "starting"
		case eaclient.UnitStateConfiguring:
			return "configuring"
		case eaclient.UnitStateHealthy:
			return "healthy"
		case eaclient.UnitStateDegraded:
			return degraded
		case eaclient.UnitStateFailed:
			return "failed"
		case eaclient.UnitStateStopping:
			return "stopping"
		case eaclient.UnitStateStopped:
			return "stopped"
		}
		return ""
	}

	unitTypeString := func(t eaclient.UnitType) string {
		switch t {
		case eaclient.UnitTypeInput:
			return "input"
		case eaclient.UnitTypeOutput:
			return "output"
		}
		return ""
	}

	checkinComponents := make([]fleetapi.CheckinComponent, 0, len(components))

	for _, item := range components {
		component := item.Component
		state := item.State

		var shipperReference *fleetapi.CheckinShipperReference
		if component.Shipper != nil {
			shipperReference = &fleetapi.CheckinShipperReference{
				ComponentID: component.Shipper.ComponentID,
				UnitID:      component.Shipper.UnitID,
			}
		}
		checkinComponent := fleetapi.CheckinComponent{
			ID:      component.ID,
			Type:    component.Type(),
			Status:  stateString(state.State),
			Message: state.Message,
			Shipper: shipperReference,
		}

		if state.Units != nil {
			units := make([]fleetapi.CheckinUnit, 0, len(state.Units))

			for unitKey, unitState := range state.Units {
				units = append(units, fleetapi.CheckinUnit{
					ID:      unitKey.UnitID,
					Type:    unitTypeString(unitKey.UnitType),
					Status:  stateString(unitState.State),
					Message: unitState.Message,
					Payload: unitState.Payload,
				})
			}
			checkinComponent.Units = units
		}
		checkinComponents = append(checkinComponents, checkinComponent)
	}

	return checkinComponents
}

func (f *fleetGateway) execute(ctx context.Context) (*fleetapi.CheckinResponse, error) {
	ecsMeta, err := info.Metadata()
	if err != nil {
		f.log.Error(errors.New("failed to load metadata", err))
	}

	// retrieve ack token from the store
	ackToken := f.stateStore.AckToken()
	if ackToken != "" {
		f.log.Debugf("using previously saved ack token: %v", ackToken)
	}

	// get current state
	state := f.stateFetcher.State()

	// convert components into checkin components structure
	components := f.convertToCheckinComponents(state.Components)

	// checkin
	cmd := fleetapi.NewCheckinCmd(f.agentInfo, f.client)
	req := &fleetapi.CheckinRequest{
		AckToken:   ackToken,
		Metadata:   ecsMeta,
		Status:     agentStateToString(state.State),
		Message:    state.Message,
		Components: components,
	}

	resp, err := cmd.Execute(ctx, req)
	if isUnauth(err) {
		f.unauthCounter++

		if f.shouldUnenroll() {
			f.log.Warnf("retrieved an invalid api key error '%d' times. Starting to unenroll the elastic agent.", f.unauthCounter)
			return &fleetapi.CheckinResponse{
				Actions: []fleetapi.Action{&fleetapi.ActionUnenroll{ActionID: "", ActionType: "UNENROLL", IsDetected: true}},
			}, nil
		}

		return nil, err
	}

	f.unauthCounter = 0
	if err != nil {
		return nil, err
	}

	// Save the latest ackToken
	if resp.AckToken != "" {
		f.stateStore.SetAckToken(resp.AckToken)
		serr := f.stateStore.Save()
		if serr != nil {
			f.log.Errorf("failed to save the ack token, err: %v", serr)
		}
	}

	return resp, nil
}

// shouldUnenroll checks if the max number of trying an invalid key is reached
func (f *fleetGateway) shouldUnenroll() bool {
	return f.unauthCounter > maxUnauthCounter
}

func isUnauth(err error) bool {
	return errors.Is(err, client.ErrInvalidAPIKey)
}

func (f *fleetGateway) SetClient(c client.Sender) {
	f.client = c
}

func agentStateToString(state agentclient.State) string {
	switch state {
	case agentclient.Healthy:
		return "online"
	case agentclient.Failed:
		return "error"
	}
	return degraded
}
