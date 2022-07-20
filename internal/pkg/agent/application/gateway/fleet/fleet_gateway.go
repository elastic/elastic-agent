// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package fleet

import (
	"context"
	stderr "errors"
	"fmt"
	"time"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/coordinator"
	dispatcher2 "github.com/elastic/elastic-agent/internal/pkg/agent/application/dispatcher"
	agentclient "github.com/elastic/elastic-agent/internal/pkg/agent/control/client"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi/acker"

	"github.com/elastic/elastic-agent/internal/pkg/fleetapi/client"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/gateway"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/internal/pkg/core/backoff"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi"
	"github.com/elastic/elastic-agent/internal/pkg/scheduler"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

// Max number of times an invalid API Key is checked
const maxUnauthCounter int = 6

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
	SetQueue([]fleetapi.Action)
	Actions() []fleetapi.Action
}

type actionQueue interface {
	Add(fleetapi.Action, int64)
	DequeueActions() []fleetapi.Action
	Cancel(string) int
	Actions() []fleetapi.Action
}

type fleetGateway struct {
	log           *logger.Logger
	dispatcher    dispatcher2.Dispatcher
	client        client.Sender
	scheduler     scheduler.Scheduler
	settings      *fleetGatewaySettings
	agentInfo     agentInfo
	acker         acker.Acker
	unauthCounter int
	stateFetcher  coordinator.StateFetcher
	stateStore    stateStore
	queue         actionQueue
	errCh         chan error
}

// New creates a new fleet gateway
func New(
	log *logger.Logger,
	agentInfo agentInfo,
	client client.Sender,
	d dispatcher2.Dispatcher,
	acker acker.Acker,
	stateFetcher coordinator.StateFetcher,
	stateStore stateStore,
	queue actionQueue,
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
		queue,
	)
}

func newFleetGatewayWithScheduler(
	log *logger.Logger,
	settings *fleetGatewaySettings,
	agentInfo agentInfo,
	client client.Sender,
	d dispatcher2.Dispatcher,
	scheduler scheduler.Scheduler,
	acker acker.Acker,
	stateFetcher coordinator.StateFetcher,
	stateStore stateStore,
	queue actionQueue,
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
		queue:        queue,
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
		case ts := <-f.scheduler.WaitTick():
			f.log.Debug("FleetGateway calling Checkin API")

			// Execute the checkin call and for any errors returned by the fleet-server API
			// the function will retry to communicate with fleet-server with an exponential delay and some
			// jitter to help better distribute the load from a fleet of agents.
			resp, err := f.doExecute(ctx, backoff)
			if err != nil {
				continue
			}

			actions := f.queueScheduledActions(resp.Actions)
			actions, err = f.dispatchCancelActions(actions)
			if err != nil {
				f.log.Error(err.Error())
			}

			queued, expired := f.gatherQueuedActions(ts.UTC())
			f.log.Debugf("Gathered %d actions from queue, %d actions expired", len(queued), len(expired))
			f.log.Debugf("Expired actions: %v", expired)

			actions = append(actions, queued...)

			// Persist state
			hadErr := false
			f.stateStore.SetQueue(f.queue.Actions())
			if err := f.stateStore.Save(); err != nil {
				err = fmt.Errorf("failed to persist action_queue, error: %w", err)
				f.log.Error(err)
				f.errCh <- err
				hadErr = true
			}

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

// queueScheduledActions will add any action in actions with a valid start time to the queue and return the rest.
// start time to current time comparisons are purposefully not made in case of cancel actions.
func (f *fleetGateway) queueScheduledActions(input fleetapi.Actions) []fleetapi.Action {
	actions := make([]fleetapi.Action, 0, len(input))
	for _, action := range input {
		start, err := action.StartTime()
		if err == nil {
			f.log.Debugf("Adding action id: %s to queue.", action.ID())
			f.queue.Add(action, start.Unix())
			continue
		}
		if !stderr.Is(err, fleetapi.ErrNoStartTime) {
			f.log.Warnf("Issue gathering start time from action id %s: %v", action.ID(), err)
		}
		actions = append(actions, action)
	}
	return actions
}

// dispatchCancelActions will separate and dispatch any cancel actions from the actions list and return the rest of the list.
// cancel actions are dispatched seperatly as they may remove items from the queue.
func (f *fleetGateway) dispatchCancelActions(actions []fleetapi.Action) ([]fleetapi.Action, error) {
	// separate cancel actions from the actions list
	cancelActions := make([]fleetapi.Action, 0, len(actions))
	for i := len(actions) - 1; i >= 0; i-- {
		action := actions[i]
		if action.Type() == fleetapi.ActionTypeCancel {
			cancelActions = append(cancelActions, action)
			actions = append(actions[:i], actions[i+1:]...)
		}
	}
	// Dispatch cancel actions
	if len(cancelActions) > 0 {
		if err := f.dispatcher.Dispatch(context.Background(), f.acker, cancelActions...); err != nil {
			return actions, fmt.Errorf("failed to dispatch cancel actions: %w", err)
		}
	}
	return actions, nil
}

// gatherQueuedActions will dequeue actions from the action queue and separate those that have already expired.
func (f *fleetGateway) gatherQueuedActions(ts time.Time) (queued, expired []fleetapi.Action) {
	actions := f.queue.DequeueActions()
	for _, action := range actions {
		exp, _ := action.Expiration()
		if ts.After(exp) {
			expired = append(expired, action)
			continue
		}
		queued = append(queued, action)
	}
	return queued, expired
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

	// checkin
	cmd := fleetapi.NewCheckinCmd(f.agentInfo, f.client)
	req := &fleetapi.CheckinRequest{
		AckToken: ackToken,
		Metadata: ecsMeta,
		Status:   agentStateToString(state.State),
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
	return "degraded"
}
