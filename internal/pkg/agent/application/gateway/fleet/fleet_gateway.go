// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package fleet

import (
	"context"
	"reflect"
	"time"

	"github.com/gofrs/uuid"

	agentclient "github.com/elastic/elastic-agent/pkg/control/v2/client"

	eaclient "github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/coordinator/state"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
	"github.com/elastic/elastic-agent/internal/pkg/agent/configuration"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/internal/pkg/core/backoff"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi/acker"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi/client"
	"github.com/elastic/elastic-agent/internal/pkg/help"
	"github.com/elastic/elastic-agent/internal/pkg/scheduler"
	"github.com/elastic/elastic-agent/pkg/component/runtime"
)

// Max number of times an invalid API Key is checked
const maxUnauthCounter int = 6

// Consts for states at fleet checkin
const fleetStateDegraded = "DEGRADED"
const fleetStateOnline = "online"
const fleetStateError = "error"
const fleetStateStarting = "starting"

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

type loggerIF interface {
	Debug(args ...interface{})
	Debugf(format string, args ...interface{})
	Info(args ...interface{})
	Infof(format string, args ...interface{})
	Infow(format string, args ...interface{})
	Warnf(format string, args ...interface{})
	Warnw(msg string, keysAndValues ...interface{})
	Error(args ...interface{})
	Errorf(format string, args ...interface{})
	Errorw(msg string, keysAndValues ...interface{})
}

type checkinResult struct {
	response *fleetapi.CheckinResponse
	err      error
}

type needNewCheckinError struct {
	newState state.State
}

func (*needNewCheckinError) Error() string {
	return "new checkin needed due to updated state"
}

type CheckinCtxKey string

const CheckinIDKey CheckinCtxKey = "checkinID"

const cancelCheckinTimeout = 1 * time.Second

type fleetGateway struct {
	log                loggerIF
	client             client.Sender
	scheduler          Scheduler
	debouncerFunction  debouncerFunc[state.State]
	settings           *configuration.FleetGatewaySettings
	cancelTimeout      time.Duration
	agentInfo          agentInfo
	acker              acker.Acker
	unauthCounter      int
	checkinFailCounter int
	stateFetcher       StateFetcher
	stateStore         stateStore
	errCh              chan error
	actionCh           chan []fleetapi.Action
}

// New creates a new fleet gateway
func New(
	log loggerIF,
	settings *configuration.FleetGatewaySettings,
	agentInfo agentInfo,
	client client.Sender,
	acker acker.Acker,
	stateFetcher StateFetcher,
	stateStore stateStore,
) (*fleetGateway, error) {

	scheduler := scheduler.NewPeriodicJitter(settings.Duration, settings.Jitter)
	debouncerFunction := Debounce[state.State]
	return newFleetGatewayWithSchedulerAndDebouncer(
		log,
		settings,
		agentInfo,
		client,
		scheduler,
		debouncerFunction,
		cancelCheckinTimeout,
		acker,
		stateFetcher,
		stateStore,
	)
}

func newFleetGatewayWithSchedulerAndDebouncer(
	log loggerIF,
	settings *configuration.FleetGatewaySettings,
	agentInfo agentInfo,
	client client.Sender,
	scheduler Scheduler,
	df debouncerFunc[state.State],
	cancelTimeout time.Duration,
	acker acker.Acker,
	stateFetcher StateFetcher,
	stateStore stateStore,
) (*fleetGateway, error) {
	return &fleetGateway{
		log:               log,
		client:            client,
		settings:          settings,
		agentInfo:         agentInfo,
		scheduler:         scheduler,
		cancelTimeout:     cancelTimeout,
		debouncerFunction: df,
		acker:             acker,
		stateFetcher:      stateFetcher,
		stateStore:        stateStore,
		errCh:             make(chan error),
		actionCh:          make(chan []fleetapi.Action, 1),
	}, nil
}

func (f *fleetGateway) Actions() <-chan []fleetapi.Action {
	return f.actionCh
}

func (f *fleetGateway) Run(ctx context.Context) error {
	f.log.Info("Fleet gateway started")
	f.log.Debugf("Fleet gateway settings: %+v", f.settings)
	for {
		select {
		case <-ctx.Done():
			f.scheduler.Stop()
			f.log.Info("Fleet gateway stopped")
			return ctx.Err()
		case <-f.scheduler.WaitTick():
			f.log.Debug("FleetGateway calling Checkin API")

			checkinResponse, err := f.triggerCheckin(ctx)
			if err != nil {
				f.log.Errorf("triggering checkin failed: %v", err)
				continue
			}

			f.log.Debug("Processing checkin response")
			actions := make([]fleetapi.Action, len(checkinResponse.Actions))
			copy(actions, checkinResponse.Actions)
			if len(actions) > 0 {
				f.actionCh <- actions
			}
		}
	}
}

func (f *fleetGateway) triggerCheckin(ctx context.Context) (*fleetapi.CheckinResponse, error) {

	// create a subcontext for this checkin and the state subscription
	stateUpdateSubCtx, cancelStateUpdateSub := context.WithCancel(ctx)
	defer func() {
		cancelStateUpdateSub()
	}()

	// Backoff implementation doesn't support the use of a context [cancellation] as the shutdown mechanism.
	// So we keep a done channel that will be closed when the current context is shutdown.
	done := make(chan struct{})
	backoff := backoff.NewEqualJitterBackoff(
		done,
		f.settings.Backoff.Init,
		f.settings.Backoff.Max,
	)
	go func() {
		<-stateUpdateSubCtx.Done()
		close(done)
	}()

	// get current state
	stateUpdateCh := f.stateFetcher.StateSubscribe(stateUpdateSubCtx).Ch()
	state := <-stateUpdateCh

	for {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}

		checkinResult := f.performCancellableCheckin(ctx, state, stateUpdateCh, backoff)

		if checkinResult.err != nil {
			var relaunchCheckinErr *needNewCheckinError
			if errors.As(checkinResult.err, &relaunchCheckinErr) {
				// checkin was cancelled because we have an updated state to send to fleet
				state = relaunchCheckinErr.newState
			}

			continue
		}

		// if we got here the checkin has been completed
		return checkinResult.response, nil
	}
}

func (f *fleetGateway) performCancellableCheckin(ctx context.Context, initialState state.State, stateUpdates <-chan state.State, backoff backoff.Backoff) checkinResult {
	checkinID, _ := uuid.NewV4()
	checkinCtx, cancelCheckinCtxFunc := context.WithCancel(ctx)
	checkinCtx = context.WithValue(checkinCtx, CheckinIDKey, checkinID.String())
	f.log.Debugf("starting checkin %q", checkinID.String())
	defer func() {
		// make sure we don't leak contexts whatever happens
		cancelCheckinCtxFunc()
	}()

	// Execute the checkin call asynchronously. For any errors returned by the fleet-server API
	// the function will retry to communicate with fleet-server with an exponential delay and some
	// jitter to help better distribute the load from a fleet of agents.
	resCheckinChan := f.doExecuteAsync(checkinCtx, backoff, initialState)
	debounceDuration := f.settings.Debounce
	for {
		select {
		case <-ctx.Done():
			return checkinResult{err: ctx.Err()}
		case checkinResult := <-resCheckinChan:
			return checkinResult
		case newState, ok := <-f.debouncerFunction(checkinCtx, stateUpdates, debounceDuration):
			if !ok {
				// update channel is closed with no value
				continue
			}

			if !reflect.DeepEqual(newState, initialState) {
				f.log.Debugf(
					"Received updated state (Agent state: %q) when checkin is ongoing past configured debounce. Cancelling previous checkin %q and starting a new one.",
					newState.State,
					checkinID.String(),
				)
				cancelCheckinTimeoutCtx, cancelCancelCheckin := context.WithTimeout(ctx, f.cancelTimeout)
				defer cancelCancelCheckin()
				f.cancelCheckin(cancelCheckinTimeoutCtx, checkinID.String(), cancelCheckinCtxFunc, resCheckinChan)
				return checkinResult{err: &needNewCheckinError{newState: newState}}
			}
			// reset the debounce duration to zero to get the next update immediately (we already waited for a debounce duration anyway without cancelling and sending a new state)
			debounceDuration = 0
		}
	}

}

func (f *fleetGateway) cancelCheckin(ctx context.Context, checkinID string, cancelCheckin context.CancelFunc, resCheckinChan <-chan checkinResult) {
	f.log.Debugf("Cancelling checkin %q", checkinID)
	cancelCheckin()
	select {
	case cancelledCheckinRes := <-resCheckinChan:
		f.log.Debugf("Reaped answer for cancelled checkin %q: %+v", checkinID, cancelledCheckinRes)
	case <-ctx.Done():
		f.log.Debugf("Context expired while waiting for cancelled checkin %q to terminate", checkinID)
	}
}

// Errors returns the channel to watch for reported errors.
func (f *fleetGateway) Errors() <-chan error {
	return f.errCh
}

// Asynchronous version of doExecute()
func (f *fleetGateway) doExecuteAsync(ctx context.Context, bo backoff.Backoff, state state.State) <-chan checkinResult {
	resChan := make(chan checkinResult)
	go func() {
		defer close(resChan)
		resp, err := f.doExecute(ctx, bo, state)
		resChan <- checkinResult{response: resp, err: err}
	}()
	return resChan
}

func (f *fleetGateway) doExecute(ctx context.Context, bo backoff.Backoff, state state.State) (*fleetapi.CheckinResponse, error) {
	bo.Reset()

	// Guard if the context is stopped by a out of bound call,
	// this mean we are rebooting to change the log level or the system is shutting us down.
	for ctx.Err() == nil {
		f.log.Debugf("Checkin started")
		resp, took, err := f.execute(ctx, state)
		if err != nil {

			if errors.Is(err, context.Canceled) {
				// the checkin was explicitly canceled
				f.log.Infow("Ongoing checkin with fleet-server has been explicitly canceled, won't be retried",
					"error.message", err, "request_duration_ns", took, "failed_checkins", f.checkinFailCounter)
				return resp, err
			}

			f.checkinFailCounter++

			// Report the first two failures at warn level as they may be recoverable with retries.
			if f.checkinFailCounter <= 2 {
				f.log.Warnw("Possible transient error during checkin with fleet-server, retrying",
					"error.message", err, "request_duration_ns", took, "failed_checkins", f.checkinFailCounter,
					"retry_after_ns", bo.NextWait())
			} else {
				f.log.Errorw("Cannot checkin in with fleet-server, retrying. "+help.GetTroubleshootMessage(),
					"error.message", err, "request_duration_ns", took, "failed_checkins", f.checkinFailCounter,
					"retry_after_ns", bo.NextWait())
			}

			if !bo.Wait() {
				// Something bad has happened and we log it and we should update our current state.
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
			f.log.Errorf("Checkin request to fleet-server succeeded after %d failures", f.checkinFailCounter)
		}

		f.checkinFailCounter = 0
		f.errCh <- nil
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
			return "STARTING"
		case eaclient.UnitStateConfiguring:
			return "CONFIGURING"
		case eaclient.UnitStateHealthy:
			return "HEALTHY"
		case eaclient.UnitStateDegraded:
			return fleetStateDegraded
		case eaclient.UnitStateFailed:
			return "FAILED"
		case eaclient.UnitStateStopping:
			return "STOPPING"
		case eaclient.UnitStateStopped:
			return "STOPPED"
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

func (f *fleetGateway) execute(ctx context.Context, state state.State) (*fleetapi.CheckinResponse, time.Duration, error) {
	ecsMeta, err := info.Metadata(f.log)
	if err != nil {
		f.log.Error(errors.New("failed to load metadata", err))
	}

	// retrieve ack token from the store
	ackToken := f.stateStore.AckToken()
	if ackToken != "" {
		f.log.Debugf("using previously saved ack token: %v", ackToken)
	}

	// convert components into checkin components structure
	components := f.convertToCheckinComponents(state.Components)

	// checkin
	cmd := fleetapi.NewCheckinCmd(f.agentInfo, f.client)
	req := &fleetapi.CheckinRequest{
		AckToken:    ackToken,
		Metadata:    ecsMeta,
		Status:      agentStateToString(state.State),
		Message:     state.Message,
		Components:  components,
		PollTimeout: fleetapi.CheckinDuration(f.client.Timeout()),
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
		return fleetStateOnline
	case agentclient.Failed:
		return fleetStateError
	case agentclient.Starting:
		return fleetStateStarting
	}
	return fleetStateDegraded
}
