// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package fleet

import (
	"context"
	"time"

	agentclient "github.com/elastic/elastic-agent/pkg/control/v2/client"

	eaclient "github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/coordinator"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
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

// Consts for states at fleet checkin
const fleetStateDegraded = "DEGRADED"
const fleetStateOnline = "online"
const fleetStateError = "error"
const fleetStateStarting = "starting"

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
	AckToken() string
	SetAckToken(ackToken string)
	Save() error
}

type FleetGateway struct {
	log                *logger.Logger
	client             client.Sender
	scheduler          scheduler.Scheduler
	settings           *fleetGatewaySettings
	agentInfo          agentInfo
	acker              acker.Acker
	unauthCounter      int
	checkinFailCounter int
	stateFetcher       func() coordinator.State
	stateStore         stateStore
	errCh              chan error
	actionCh           chan []fleetapi.Action
}

// New creates a new fleet gateway
func New(
	log *logger.Logger,
	agentInfo agentInfo,
	client client.Sender,
	acker acker.Acker,
	stateFetcher func() coordinator.State,
	stateStore stateStore,
) (*FleetGateway, error) {

	scheduler := scheduler.NewPeriodicJitter(defaultGatewaySettings.Duration, defaultGatewaySettings.Jitter)
	return newFleetGatewayWithScheduler(
		log,
		defaultGatewaySettings,
		agentInfo,
		client,
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
	scheduler scheduler.Scheduler,
	acker acker.Acker,
	stateFetcher func() coordinator.State,
	stateStore stateStore,
) (*FleetGateway, error) {
	return &FleetGateway{
		log:          log,
		client:       client,
		settings:     settings,
		agentInfo:    agentInfo,
		scheduler:    scheduler,
		acker:        acker,
		stateFetcher: stateFetcher,
		stateStore:   stateStore,
		errCh:        make(chan error),
		actionCh:     make(chan []fleetapi.Action, 1),
	}, nil
}

func (f *FleetGateway) Actions() <-chan []fleetapi.Action {
	return f.actionCh
}

func (f *FleetGateway) Run(ctx context.Context) error {
	backoff := backoff.NewEqualJitterBackoff(
		ctx.Done(),
		f.settings.Backoff.Init,
		f.settings.Backoff.Max,
	)
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
			if len(actions) > 0 {
				f.actionCh <- actions
			}
		}
	}
}

// Errors returns the channel to watch for reported errors.
func (f *FleetGateway) Errors() <-chan error {
	return f.errCh
}

func (f *FleetGateway) doExecute(ctx context.Context, bo backoff.Backoff) (*fleetapi.CheckinResponse, error) {
	bo.Reset()

	// Guard if the context is stopped by a out of bound call,
	// this mean we are rebooting to change the log level or the system is shutting us down.
	for ctx.Err() == nil {
		f.log.Debugf("Checking started")
		resp, took, err := f.execute(ctx)
		if err != nil {
			f.checkinFailCounter++

			// Report the first two failures at warn level as they may be recoverable with retries.
			if f.checkinFailCounter <= 2 {
				f.log.Warnw("Possible transient error during checkin with fleet-server, retrying",
					"error.message", err, "request_duration_ns", took, "failed_checkins", f.checkinFailCounter,
					"retry_after_ns", bo.NextWait())
			} else {
				f.log.Errorw("Cannot checkin in with fleet-server, retrying",
					"error.message", err, "request_duration_ns", took, "failed_checkins", f.checkinFailCounter,
					"retry_after_ns", bo.NextWait())
			}

			if !bo.Wait() {
				if ctx.Err() != nil {
					// if the context is cancelled, break out of the loop
					break
				}

				// This should not really happen, but just in-case this error is used to show that
				// something strange occurred and we want to log it and report it.
				err := errors.New(
					"checkin retry loop was stopped",
					errors.TypeNetwork,
					errors.M(errors.MetaKeyURI, f.client.URI()),
				)

				f.log.Error(err)
				f.errCh <- err
				return nil, err
			}
			f.errCh <- err
			continue
		}

		if f.checkinFailCounter > 0 {
			// Log at same level as error logs above so subsequent successes are visible when log level is set to 'error'.
			f.log.Warnf("Checkin request to fleet-server succeeded after %d failures", f.checkinFailCounter)
		}

		f.checkinFailCounter = 0
		if resp.FleetWarning != "" {
			f.errCh <- coordinator.NewWarningError(resp.FleetWarning)
		} else {
			f.errCh <- nil
		}

		// Request was successful, return the collected actions.
		return resp, nil
	}

	// This mean that the next loop was cancelled because of the context, we should return the error
	// but we should not log it, because we are in the process of shutting down.
	return nil, ctx.Err()
}

func (f *FleetGateway) convertToCheckinComponents(components []runtime.ComponentComponentState) []fleetapi.CheckinComponent {
	if components == nil {
		return nil
	}
	stateString := func(s eaclient.UnitState) string {
		if state := s.String(); state != "UNKNOWN" {
			return state
		}
		return ""
	}

	unitTypeString := func(t eaclient.UnitType) string {
		if typ := t.String(); typ != "unknown" {
			return typ
		}
		return ""
	}

	checkinComponents := make([]fleetapi.CheckinComponent, 0, len(components))

	for _, item := range components {
		component := item.Component
		state := item.State

		checkinComponent := fleetapi.CheckinComponent{
			ID:      component.ID,
			Type:    component.Type(),
			Status:  stateString(state.State),
			Message: state.Message,
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

func (f *FleetGateway) execute(ctx context.Context) (*fleetapi.CheckinResponse, time.Duration, error) {
	ecsMeta, err := info.Metadata(ctx, f.log)
	if err != nil {
		f.log.Error(errors.New("failed to load metadata", err))
	}

	// retrieve ack token from the store
	ackToken := f.stateStore.AckToken()
	if ackToken != "" {
		f.log.Debugf("using previously saved ack token: %v", ackToken)
	}

	// get current state
	state := f.stateFetcher()

	// convert components into checkin components structure
	components := f.convertToCheckinComponents(state.Components)

	f.log.Debugf("correcting agent loglevel from %s to %s using coordinator state", ecsMeta.Elastic.Agent.LogLevel, state.LogLevel.String())
	// Fix loglevel with the current log level used by coordinator
	ecsMeta.Elastic.Agent.LogLevel = state.LogLevel.String()

	// checkin
	cmd := fleetapi.NewCheckinCmd(f.agentInfo, f.client)
	req := &fleetapi.CheckinRequest{
		AckToken:       ackToken,
		Metadata:       ecsMeta,
		Status:         agentStateToString(state.State),
		Message:        state.Message,
		Components:     components,
		UpgradeDetails: state.UpgradeDetails,
	}

	resp, took, err := cmd.Execute(ctx, req)
	if isUnauth(err) {
		f.unauthCounter++

		if f.shouldUnenroll() {
			f.log.Warnf("retrieved an invalid api key error '%d' times. Starting to unenroll the elastic agent.", f.unauthCounter)
			return &fleetapi.CheckinResponse{
				Actions: []fleetapi.Action{&fleetapi.ActionUnenroll{ActionID: "", ActionType: "UNENROLL", IsDetected: true}},
			}, took, nil
		}

		return nil, took, err
	}

	f.unauthCounter = 0
	if err != nil {
		return nil, took, err
	}

	// Save the latest ackToken
	if resp.AckToken != "" {
		f.stateStore.SetAckToken(resp.AckToken)
		serr := f.stateStore.Save()
		if serr != nil {
			f.log.Errorf("failed to save the ack token, err: %v", serr)
		}
	}

	return resp, took, nil
}

// shouldUnenroll checks if the max number of trying an invalid key is reached
func (f *FleetGateway) shouldUnenroll() bool {
	return f.unauthCounter > maxUnauthCounter
}

func isUnauth(err error) bool {
	return errors.Is(err, client.ErrInvalidAPIKey)
}

func (f *FleetGateway) SetClient(c client.Sender) {
	f.client = c
}

func agentStateToString(state agentclient.State) string {
	switch state {
	case agentclient.Healthy:
		return fleetStateOnline
	case agentclient.Failed:
		return fleetStateError
	case agentclient.Starting:
		return fleetStateStarting
	case agentclient.Configuring:
		return fleetStateOnline
	case agentclient.Upgrading:
		return fleetStateOnline
	case agentclient.Rollback:
		return fleetStateDegraded
	case agentclient.Degraded:
		return fleetStateDegraded
	// Report Stopping and Stopped as online since Fleet doesn't understand these states yet.
	// Usually Stopping and Stopped mean the agent is going to stop checking in at which point Fleet
	// will update the state to offline. Use the online state here since there isn't anything better
	// at the moment, and the agent will end up in the expected offline state eventually.
	case agentclient.Stopping:
		return fleetStateOnline
	case agentclient.Stopped:
		return fleetStateOnline
	}
	// Unknown states map to degraded.
	return fleetStateDegraded
}
