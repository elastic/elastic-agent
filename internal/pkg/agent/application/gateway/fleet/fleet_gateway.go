// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

// Package fleet handles interactions between the elastic-agent and fleet-server.
// Specifically it will handle agent checkins, and action queueing/dispatch.
package fleet

import (
	"context"
	stderr "errors"
	"fmt"
	"sync"
	"time"

	"github.com/elastic/elastic-agent/internal/pkg/core/state"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi/client"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/gateway"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/pipeline"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/internal/pkg/agent/storage/store"
	"github.com/elastic/elastic-agent/internal/pkg/core/backoff"
	"github.com/elastic/elastic-agent/internal/pkg/core/status"
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
	bgContext          context.Context
	log                *logger.Logger
	dispatcher         pipeline.Dispatcher
	client             client.Sender
	scheduler          scheduler.Scheduler
	backoff            backoff.Backoff
	settings           *fleetGatewaySettings
	agentInfo          agentInfo
	done               chan struct{}
	wg                 sync.WaitGroup
	acker              store.FleetAcker
	unauthCounter      int
	checkinFailCounter int
	statusController   status.Controller
	statusReporter     status.Reporter
	localReporter      status.Reporter
	stateStore         stateStore
	queue              actionQueue
}

// New creates a new fleet gateway
func New(
	ctx context.Context,
	log *logger.Logger,
	agentInfo agentInfo,
	client client.Sender,
	d pipeline.Dispatcher,
	acker store.FleetAcker,
	statusController status.Controller,
	stateStore stateStore,
	queue actionQueue,
) (gateway.FleetGateway, error) {

	scheduler := scheduler.NewPeriodicJitter(defaultGatewaySettings.Duration, defaultGatewaySettings.Jitter)
	return newFleetGatewayWithScheduler(
		ctx,
		log,
		defaultGatewaySettings,
		agentInfo,
		client,
		d,
		scheduler,
		acker,
		statusController,
		stateStore,
		queue,
	)
}

func newFleetGatewayWithScheduler(
	ctx context.Context,
	log *logger.Logger,
	settings *fleetGatewaySettings,
	agentInfo agentInfo,
	client client.Sender,
	d pipeline.Dispatcher,
	scheduler scheduler.Scheduler,
	acker store.FleetAcker,
	statusController status.Controller,
	stateStore stateStore,
	queue actionQueue,
) (gateway.FleetGateway, error) {

	// Backoff implementation doesn't support the use of a context [cancellation]
	// as the shutdown mechanism.
	// So we keep a done channel that will be closed when the current context is shutdown.
	done := make(chan struct{})

	return &fleetGateway{
		bgContext:  ctx,
		log:        log,
		dispatcher: d,
		client:     client,
		settings:   settings,
		agentInfo:  agentInfo,
		scheduler:  scheduler,
		backoff: backoff.NewEqualJitterBackoff(
			done,
			settings.Backoff.Init,
			settings.Backoff.Max,
		),
		done:             done,
		acker:            acker,
		statusReporter:   statusController.RegisterComponent("gateway"),
		localReporter:    statusController.RegisterLocalComponent("gateway-checkin"),
		statusController: statusController,
		stateStore:       stateStore,
		queue:            queue,
	}, nil
}

func (f *fleetGateway) worker() {
	for {
		select {
		case ts := <-f.scheduler.WaitTick():
			f.log.Debug("FleetGateway calling Checkin API")

			// Execute the checkin call and for any errors returned by the fleet-server API
			// the function will retry to communicate with fleet-server with an exponential delay and some
			// jitter to help better distribute the load from a fleet of agents.
			resp, err := f.executeCheckinWithRetries()
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

			var errMsg string
			// Persist state
			f.stateStore.SetQueue(f.queue.Actions())
			if err := f.stateStore.Save(); err != nil {
				errMsg = fmt.Sprintf("failed to persist action_queue, error: %s", err)
				f.log.Error(errMsg)
				f.statusReporter.Update(state.Failed, errMsg, nil)
			}

			if err := f.dispatcher.Dispatch(context.Background(), f.acker, actions...); err != nil {
				errMsg = fmt.Sprintf("failed to dispatch actions, error: %s", err)
				f.log.Error(errMsg)
				f.statusReporter.Update(state.Failed, errMsg, nil)
			}

			f.log.Debugf("FleetGateway is sleeping, next update in %s", f.settings.Duration)
			if errMsg != "" {
				f.statusReporter.Update(state.Failed, errMsg, nil)
			} else {
				f.statusReporter.Update(state.Healthy, "", nil)
				f.localReporter.Update(state.Healthy, "", nil) // we don't need to specifically set the local reporter to failed above, but it needs to be reset to healthy if a checkin succeeds
			}

		case <-f.bgContext.Done():
			f.stop()
			return
		}
	}
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

func (f *fleetGateway) executeCheckinWithRetries() (*fleetapi.CheckinResponse, error) {
	f.backoff.Reset()

	// Guard if the context is stopped by a out of bound call,
	// this mean we are rebooting to change the log level or the system is shutting us down.
	for f.bgContext.Err() == nil {
		f.log.Debugf("Checkin started")
		resp, took, err := f.executeCheckin(f.bgContext)
		if err != nil {
			f.checkinFailCounter++

			// Report the first two failures at warn level as they may be recoverable with retries.
			if f.checkinFailCounter <= 2 {
				f.log.Warnw("Possible transient error during checkin with fleet-server, retrying",
					"error.message", err, "request_duration_ns", took, "failed_checkins", f.checkinFailCounter,
					"retry_after_ns", f.backoff.NextWait())
			} else {
				// Only update the local status after repeated failures: https://github.com/elastic/elastic-agent/issues/1148
				f.localReporter.Update(state.Degraded, fmt.Sprintf("checkin failed: %v", err), nil)
				f.log.Errorw("Cannot checkin in with fleet-server, retrying",
					"error.message", err, "request_duration_ns", took, "failed_checkins", f.checkinFailCounter,
					"retry_after_ns", f.backoff.NextWait())
			}

			if !f.backoff.Wait() {
				// Something bad has happened and we log it and we should update our current state.
				err := errors.New(
					"checkin retry loop was stopped",
					errors.TypeNetwork,
					errors.M(errors.MetaKeyURI, f.client.URI()),
				)

				f.log.Error(err)
				f.localReporter.Update(state.Failed, err.Error(), nil)
				return nil, err
			}
			continue
		}

		if f.checkinFailCounter > 0 {
			// Log at same level as error logs above so subsequent successes are visible when log level is set to 'error'.
			f.log.Errorf("Checkin request to fleet-server succeeded after %d failures", f.checkinFailCounter)
		}

		f.checkinFailCounter = 0
		// Request was successful, return the collected actions.
		return resp, nil
	}

	// This mean that the next loop was cancelled because of the context, we should return the error
	// but we should not log it, because we are in the process of shutting down.
	return nil, f.bgContext.Err()
}

func (f *fleetGateway) executeCheckin(ctx context.Context) (*fleetapi.CheckinResponse, time.Duration, error) {
	ecsMeta, err := info.Metadata()
	if err != nil {
		f.log.Error(errors.New("failed to load metadata", err))
	}

	// retrieve ack token from the store
	ackToken := f.stateStore.AckToken()
	if ackToken != "" {
		f.log.Debugf("using previously saved ack token: %v", ackToken)
	}

	// checkin
	cmd := fleetapi.NewCheckinCmd(f.agentInfo, f.client)
	req := &fleetapi.CheckinRequest{
		AckToken: ackToken,
		Metadata: ecsMeta,
		Status:   f.statusController.StatusString(),
		Message:  f.statusController.Status().Message,
	}

	resp, took, err := cmd.Execute(ctx, req)
	if isUnauth(err) {
		f.unauthCounter++

		if f.shouldUnenroll() {
			f.log.Warnf("received an invalid api key error '%d' times. Starting to unenroll the elastic agent.", f.unauthCounter)
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

func (f *fleetGateway) Start() error {
	f.wg.Add(1)
	go func(wg *sync.WaitGroup) {
		defer f.log.Info("Fleet gateway is stopped")
		defer wg.Done()

		f.worker()
	}(&f.wg)
	return nil
}

func (f *fleetGateway) stop() {
	f.log.Info("Fleet gateway is stopping")
	defer f.scheduler.Stop()
	f.statusReporter.Unregister()
	f.localReporter.Unregister()
	close(f.done)
	f.wg.Wait()
}

func (f *fleetGateway) SetClient(c client.Sender) {
	f.client = c
}
