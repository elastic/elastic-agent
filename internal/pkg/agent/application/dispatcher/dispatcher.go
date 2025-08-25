// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package dispatcher

import (
	"context"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"time"

	"go.elastic.co/apm/v2"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/actions"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/details"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi/acker"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

type actionHandlers map[reflect.Type]actions.Handler

type priorityQueue interface {
	Add(fleetapi.ScheduledAction, int64)
	DequeueActions() []fleetapi.ScheduledAction
	Actions() []fleetapi.ScheduledAction
	CancelType(string) int
	Save() error
}

// Dispatcher processes actions coming from fleet api.
type Dispatcher interface {
	Dispatch(context.Context, details.Observer, acker.Acker, ...fleetapi.Action)
	Errors() <-chan error
}

// ActionDispatcher processes actions coming from fleet using registered set of handlers.
type ActionDispatcher struct {
	log      *logger.Logger
	handlers actionHandlers
	def      actions.Handler
	queue    priorityQueue
	rt       *retryConfig
	errCh    chan error
	topPath  string

	lastUpgradeDetails *details.Details
}

// New creates a new action dispatcher.
func New(log *logger.Logger, topPath string, def actions.Handler, queue priorityQueue) (*ActionDispatcher, error) {
	var err error
	if log == nil {
		log, err = logger.New("action_dispatcher", false)
		if err != nil {
			return nil, err
		}
	}

	if def == nil {
		return nil, errors.New("missing default handler")
	}

	return &ActionDispatcher{
		log:      log,
		handlers: make(actionHandlers),
		def:      def,
		queue:    queue,
		rt:       defaultRetryConfig(),
		errCh:    make(chan error),
		topPath:  topPath,
	}, nil
}

func (ad *ActionDispatcher) Errors() <-chan error {
	return ad.errCh
}

// Register registers a new handler for action.
func (ad *ActionDispatcher) Register(a fleetapi.Action, handler actions.Handler) error {
	k := ad.key(a)
	_, ok := ad.handlers[k]
	if ok {
		return fmt.Errorf("action with type %s is already registered", k)
	}
	ad.handlers[k] = handler
	return nil
}

// MustRegister registers a new handler for action.
// Panics if not successful.
func (ad *ActionDispatcher) MustRegister(a fleetapi.Action, handler actions.Handler) {
	err := ad.Register(a, handler)
	if err != nil {
		panic("could not register action, error: " + err.Error())
	}
}

func (ad *ActionDispatcher) key(a fleetapi.Action) reflect.Type {
	return reflect.TypeOf(a)
}

// Dispatch dispatches an action using pre-registered set of handlers.
// Dispatch will handle action queue operations, and retries.
// Any action that implements the ScheduledAction interface may be added/removed from the queue based on StartTime.
// Any action that implements the RetryableAction interface will be rescheduled if the handler returns an error.
func (ad *ActionDispatcher) Dispatch(ctx context.Context, detailsSetter details.Observer, acker acker.Acker, actions ...fleetapi.Action) {
	var err error
	span, ctx := apm.StartSpan(ctx, "dispatch", "app.internal")
	defer func() {
		apm.CaptureError(ctx, err).Send()
		span.End()
	}()

	now := time.Now().UTC()

	// remove any upgrade actions from the queue if there is an upgrade action in the actions
	ad.removeQueuedUpgrades(actions)
	// add any scheduled actions to the queue (we don't check the start time here, as we will check it later)
	// and remove them from the passed actions
	actions = ad.queueScheduledActions(actions)
	// dispatch any cancel actions now as they may remove items from the queue
	actions = ad.dispatchCancelActions(ctx, actions, acker)

	// extract the scheduled upgrade details from the queue before calling gatherQueuedActions as
	// the latter will dequeue actions that will be dispatched now or have expired
	scheduledUpgradeDetails := GetScheduledUpgradeDetails(ad.log, ad.queue, now)

	// gather queued actions that need to be dispatched and separate expired actions
	queued, expired := ad.gatherQueuedActions(now)
	ad.log.Debugf("Gathered %d actions from queue, %d actions expired", len(queued), len(expired))
	ad.log.Debugf("Expired actions: %v", expired)

	// merge the passed actions with queued actions that need to be dispatched
	actions = append(actions, queued...)

	// if there is an upgrade action in the ones to be dispatched there is no need set the scheduled upgrade
	// details from the queue.
	containsUpgradeAction := slices.ContainsFunc(actions, func(a fleetapi.Action) bool {
		return a.Type() == fleetapi.ActionTypeUpgrade
	})
	if !containsUpgradeAction {
		detailsSetter(scheduledUpgradeDetails)
	}

	if err := ad.queue.Save(); err != nil {
		ad.log.Errorf("failed to persist action_queue: %v", err)
	}

	if len(actions) == 0 {
		ad.log.Debug("No action to dispatch")
		return
	}

	ad.log.Debugf(
		"Dispatch %d actions of types: %s",
		len(actions),
		strings.Join(detectTypes(actions), ", "),
	)

	var reportedErr error
	for _, action := range actions {
		if err = ctx.Err(); err != nil {
			ad.errCh <- err
			return
		}

		if err := ad.dispatchAction(ctx, action, acker); err != nil {
			rAction, ok := action.(fleetapi.RetryableAction)
			if ok {
				rAction.SetError(err) // set the retryable action error to what the dispatcher returned
				ad.scheduleRetry(ctx, rAction, acker)
				continue
			}
			ad.log.Errorf("Failed to dispatch action id %q of type %q, error: %+v", action.ID(), action.Type(), err)
			reportedErr = err
			continue
		}
		ad.log.Debugf("Successfully dispatched action: '%+v'", action)
	}

	if err = acker.Commit(ctx); err != nil {
		reportedErr = err
	}

	if len(actions) > 0 {
		ad.errCh <- reportedErr
	}
}

func (ad *ActionDispatcher) dispatchAction(ctx context.Context, a fleetapi.Action, acker acker.Acker) error {
	handler, found := ad.handlers[ad.key(a)]
	if !found {
		return ad.def.Handle(ctx, a, acker)
	}

	return handler.Handle(ctx, a, acker)
}

func detectTypes(actions []fleetapi.Action) []string {
	str := make([]string, len(actions))
	for idx, action := range actions {
		str[idx] = reflect.TypeOf(action).String()
	}
	return str
}

// queueScheduledActions will add any action in actions with a valid start time to the queue and return the rest.
// start time to current time comparisons are purposefully not made in case of cancel actions.
func (ad *ActionDispatcher) queueScheduledActions(input []fleetapi.Action) []fleetapi.Action {
	actions := make([]fleetapi.Action, 0, len(input))
	for _, action := range input {
		sAction, ok := action.(fleetapi.ScheduledAction)
		if ok {
			start, err := sAction.StartTime()
			if err != nil {
				if _, isUpgradeAction := sAction.(*fleetapi.ActionUpgrade); !isUpgradeAction {
					// upgrade actions can be both scheduled and immediate actions, so
					// they can appear without a start time
					ad.log.Warnf("Skipping addition to action-queue, issue gathering start time from action id %s: %v", sAction.ID(), err)
				}

				actions = append(actions, action)
				continue
			}
			ad.log.Debugf("Adding action id: %s to queue.", sAction.ID())
			ad.queue.Add(sAction, start.Unix())
			continue
		}
		actions = append(actions, action)
	}
	return actions
}

// dispatchCancelActions will separate and dispatch any cancel actions from the actions list and return the rest of the list.
// cancel actions are dispatched seperatly as they may remove items from the queue.
func (ad *ActionDispatcher) dispatchCancelActions(ctx context.Context, actions []fleetapi.Action, acker acker.Acker) []fleetapi.Action {
	for i := len(actions) - 1; i >= 0; i-- {
		action := actions[i]
		// If it is a cancel action, remove from list and dispatch
		if action.Type() == fleetapi.ActionTypeCancel {
			actions = append(actions[:i], actions[i+1:]...)
			if err := ad.dispatchAction(ctx, action, acker); err != nil {
				ad.log.Errorf("Unable to dispatch cancel action id %s: %v", action.ID(), err)
			}
		}
	}
	return actions
}

// gatherQueuedActions will dequeue actions from the action queue and separate those that have already expired.
func (ad *ActionDispatcher) gatherQueuedActions(ts time.Time) (queued, expired []fleetapi.Action) {
	actions := ad.queue.DequeueActions()
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

// removeQueuedUpgrades will scan the passed actions and if there is an upgrade action it will remove all upgrade actions in the queue but not alter the passed list.
// this is done to try to only have the most recent upgrade action executed. However it does not eliminate duplicates in retrieved directly from the gateway
func (ad *ActionDispatcher) removeQueuedUpgrades(actions []fleetapi.Action) {
	for _, action := range actions {
		if action.Type() == fleetapi.ActionTypeUpgrade {
			if n := ad.queue.CancelType(fleetapi.ActionTypeUpgrade); n > 0 {
				ad.log.Debugw("New upgrade action retrieved from gateway, removing queued upgrade actions", "actions_found", n)
			}
			return
		}
	}
}

func (ad *ActionDispatcher) scheduleRetry(ctx context.Context, action fleetapi.RetryableAction, acker acker.Acker) {
	attempt := action.RetryAttempt()
	d, err := ad.rt.GetWait(attempt)
	if err != nil {
		ad.log.Errorf("No more retries for action id %s: %v", action.ID(), err)
		action.SetRetryAttempt(-1)
		if err := acker.Ack(ctx, action); err != nil {
			ad.log.Errorf("Unable to ack action failure (id %s) to fleet-server: %v", action.ID(), err)
			return
		}
		if err := acker.Commit(ctx); err != nil {
			ad.log.Errorf("Unable to commit action failure (id %s) to fleet-server: %v", action.ID(), err)
		}
		return
	}
	attempt = attempt + 1
	startTime := time.Now().UTC().Add(d)
	action.SetRetryAttempt(attempt)
	action.SetStartTime(startTime)
	ad.log.Debugf("Adding action id: %s to queue.", action.ID())
	ad.queue.Add(action, startTime.Unix())
	err = ad.queue.Save()
	if err != nil {
		ad.log.Errorf("retry action id %s attempt %d failed to persist action_queue: %v", action.ID(), attempt, err)
	}
	if err := acker.Ack(ctx, action); err != nil {
		ad.log.Errorf("Unable to ack action retry (id %s) to fleet-server: %v", action.ID(), err)
		return
	}
	if err := acker.Commit(ctx); err != nil {
		ad.log.Errorf("Unable to commit action retry (id %s) to fleet-server: %v", action.ID(), err)
	}
}

func GetScheduledUpgradeDetails(log *logger.Logger, queue priorityQueue, ts time.Time) *details.Details {
	var nextUpgradeAction *fleetapi.ActionUpgrade
	var nextUpgradeStartTime time.Time
	var nextUpgradeExpirationTime time.Time

	for _, queuedAction := range queue.Actions() {
		scheduledAction, ok := queuedAction.(fleetapi.ScheduledAction)
		if !ok {
			continue
		}

		upgradeAction, ok := scheduledAction.(*fleetapi.ActionUpgrade)
		if !ok {
			continue
		}

		// all queued upgrade actions must have a start time
		upgradeStartTime, err := upgradeAction.StartTime()
		if err != nil {
			log.Errorf("failed to get start time for scheduled upgrade action [id = %s]: %v", upgradeAction.ID(), err)
			continue
		}

		// not all scheduled upgrade actions have an expiration, e.g. a scheduled retried upgrade because it failed
		// does not have an expiration
		upgradeExpirationTime, err := upgradeAction.Expiration()
		if err != nil {
			if !errors.Is(err, fleetapi.ErrNoExpiration) {
				// this is not a non-expiring upgrade action
				log.Errorf("failed to get expiration time for scheduled upgrade action [id = %s]: %v", upgradeAction.ID(), err)
				continue
			}
			// this is a non-expiring upgrade action
		}

		if nextUpgradeAction == nil || !upgradeStartTime.After(nextUpgradeStartTime) {
			nextUpgradeAction = upgradeAction
			nextUpgradeStartTime = upgradeStartTime
			nextUpgradeExpirationTime = upgradeExpirationTime
		}
	}

	// If there is no scheduled upgrade, nothing to do.
	if nextUpgradeAction == nil {
		return nil
	}

	nextUpgradeActionID := nextUpgradeAction.ID()
	nextUpgradeActionVersion := nextUpgradeAction.Data.Version
	if !nextUpgradeExpirationTime.IsZero() && ts.After(nextUpgradeExpirationTime) {
		// upgrade has expired
		expiration := nextUpgradeAction.ActionExpiration
		upgradeDetails := details.NewDetails(nextUpgradeActionVersion, details.StateFailed, nextUpgradeActionID)
		upgradeDetails.Fail(fmt.Errorf("upgrade action %q expired on %s", nextUpgradeActionID, expiration))
		return upgradeDetails
	}

	upgradeDetails := details.NewDetails(
		nextUpgradeActionVersion,
		details.StateScheduled,
		nextUpgradeActionID)
	upgradeDetails.Metadata.ScheduledAt = &nextUpgradeStartTime
	return upgradeDetails
}
