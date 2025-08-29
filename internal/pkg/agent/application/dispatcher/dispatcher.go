// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package dispatcher

import (
	"context"
	"fmt"
	"maps"
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
	// lastUpgradeDetails holds the last upgrade details set by the ActionDispatcher
	lastUpgradeDetails *details.Details
	// lastUpgradeDetailsIsSet is necessary to differentiate if lastUpgradeDetails is set to nil or is never set
	lastUpgradeDetailsIsSet bool
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

	upgradeDetailsNeedUpdate := false

	// remove duplicate upgrade actions from fleetgateway actions and remove all upgrade actions in the queue
	actions = ad.compactAndRemoveQueuedUpgrades(actions, &upgradeDetailsNeedUpdate)

	// add any scheduled actions to the queue (we don't check the start time here, as we will check it later)
	// and remove them from the passed actions
	actions = ad.queueScheduledActions(actions, &upgradeDetailsNeedUpdate)

	// dispatch any cancel actions now as they may remove items from the queue
	actions = ad.dispatchCancelActions(ctx, actions, &upgradeDetailsNeedUpdate, acker)

	// gather queued actions that need to be dispatched and separate expired actions
	actions = ad.mergeWithQueuedActions(now, actions, &upgradeDetailsNeedUpdate)

	if upgradeDetailsNeedUpdate {
		upgradeDetailsNeedUpdate = false
		ad.updateUpgradeDetails(now, detailsSetter)
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
				ad.scheduleRetry(ctx, rAction, acker, &upgradeDetailsNeedUpdate)
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

	if upgradeDetailsNeedUpdate {
		ad.updateUpgradeDetails(now, detailsSetter)
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
// start time to current time comparisons are purposefully not made in case of cancel actions. If upgrade actions
// are added to the queue, upgradeDetailsNeedUpdate will be set to true.
func (ad *ActionDispatcher) queueScheduledActions(input []fleetapi.Action, upgradeDetailsNeedUpdate *bool) []fleetapi.Action {
	actions := make([]fleetapi.Action, 0, len(input))
	for _, action := range input {
		sAction, ok := action.(fleetapi.ScheduledAction)
		if !ok {
			// not a scheduled action
			actions = append(actions, action)
			continue
		}

		_, isUpgradeAction := sAction.(*fleetapi.ActionUpgrade)

		start, err := sAction.StartTime()
		if err != nil {
			if !isUpgradeAction {
				// upgrade actions can be both scheduled and immediate actions, so
				// they can appear without a start time
				ad.log.Warnf("Skipping addition to action-queue, issue gathering start time from action id %s: %v", sAction.ID(), err)
			}

			actions = append(actions, action)
			continue
		}

		ad.log.Debugf("Adding action id: %s to queue.", sAction.ID())
		ad.queue.Add(sAction, start.Unix())

		if isUpgradeAction {
			// there is an upgrade action added to the queue so we need to update the upgrade details
			*upgradeDetailsNeedUpdate = true
		}
	}
	return actions
}

// dispatchCancelActions will separate and dispatch any cancel actions from the actions list and return the rest of the list.
// cancel actions are dispatched separately as they may remove items from the queue. If cancel actions remove upgrade actions
// from the queue, upgradeDetailsNeedUpdate will be set to true.
func (ad *ActionDispatcher) dispatchCancelActions(ctx context.Context, actions []fleetapi.Action, upgradeDetailsNeedUpdate *bool, acker acker.Acker) []fleetapi.Action {
	queuedUpgradeActions := maps.Collect(func(yield func(K string, V struct{}) bool) {
		for _, action := range ad.queue.Actions() {
			if _, ok := action.(*fleetapi.ActionUpgrade); !ok {
				continue
			}

			if !yield(action.ID(), struct{}{}) {
				return
			}
		}
	})

	for i := len(actions) - 1; i >= 0; i-- {
		action := actions[i]

		cancelAction, ok := action.(*fleetapi.ActionCancel)
		if !ok {
			continue
		}

		actions = append(actions[:i], actions[i+1:]...)
		if err := ad.dispatchAction(ctx, action, acker); err != nil {
			ad.log.Errorf("Unable to dispatch cancel action id %s: %v", action.ID(), err)
		}

		if _, exists := queuedUpgradeActions[cancelAction.Data.TargetID]; exists {
			*upgradeDetailsNeedUpdate = true
		}
	}
	return actions
}

// mergeWithQueuedActions will dequeue actions from the action queue, excluding those that have already expired, and merge
// them with the passed actions. If upgrade actions are found to inside the dispatchable action, upgradeDetailsNeedUpdate
// will be set to false, otherwise if upgrade actions are found to be expired, upgradeDetailsNeedUpdate will be set to true.
func (ad *ActionDispatcher) mergeWithQueuedActions(ts time.Time, actions []fleetapi.Action, upgradeDetailsNeedUpdate *bool) []fleetapi.Action {
	var expired []fleetapi.ScheduledAction
	var expiredUpgradeActions []fleetapi.ScheduledAction
	dequeuedActions := ad.queue.DequeueActions()

	for _, action := range dequeuedActions {
		exp, err := action.Expiration()
		if err != nil {
			if !errors.Is(err, fleetapi.ErrNoExpiration) {
				// this is not a non-expiring scheduled action, e.g. there is a malformed expiration time set
				ad.log.Warnf("failed to get expiration time for scheduled action [id = %s]: %v", action.ID(), err)
				continue
			}
			// this is a non-expiring scheduled action
			actions = append(actions, action)
			continue
		}
		if ts.After(exp) {
			if action.Type() == fleetapi.ActionTypeUpgrade {
				// this is an expired upgrade action thus we need to recalculate the upgrade details
				*upgradeDetailsNeedUpdate = true
				expiredUpgradeActions = append(expiredUpgradeActions, action)
			} else {
				expired = append(expired, action)
			}

			continue
		}
		actions = append(actions, action)
	}

	ad.log.Debugf("Gathered %d actions from queue, %d non-upgrade actions expired, %d upgrade actions expired",
		len(dequeuedActions), len(expired), len(expiredUpgradeActions))
	ad.log.Debugf("Expired non-upgrade actions: %v", expired)
	ad.log.Debugf("Expired upgrade actions (won't be removed from the queue): %v", expiredUpgradeActions)

	// Put expired upgrade actions back onto the queue to persist them across restarts.
	// These are handled the same as non-expired upgrade scheduled actions and are only removed when:
	// 1) a cancel action is received (look at dispatchCancelActions func) or
	// 2) a newer upgrade action (scheduled or not) removes them. (look at compactAndRemoveQueuedUpgrades func)
	for _, expiredUpgradeAction := range expiredUpgradeActions {
		startTime, err := expiredUpgradeAction.StartTime()
		if err != nil {
			// at this point expired upgrade action must have a valid start time set
			ad.log.Warnf("failed to get start time of expired upgrade action [%s]: %v", expiredUpgradeAction.ID(), err)
			continue
		}
		ad.queue.Add(expiredUpgradeAction, startTime.Unix())
	}

	// if an upgrade action is included in the immediate dispatchable actions
	// mark upgradeDetailsNeedUpdate as true
	if slices.ContainsFunc(actions, func(action fleetapi.Action) bool {
		return action.Type() == fleetapi.ActionTypeUpgrade
	}) {
		*upgradeDetailsNeedUpdate = true
	}

	return actions
}

// compactAndRemoveQueuedUpgrades deduplicates *upgrade* actions from the given fleetgateway actions by keeping only the
// first encountered upgrade in input order (dropping any subsequent upgrades from the returned slice). If an upgrade
// action is found, it also removes any queued upgrade actions from the queue. When queued upgrade actions are removed,
// upgradeDetailsNeedUpdate is set to true.
func (ad *ActionDispatcher) compactAndRemoveQueuedUpgrades(input []fleetapi.Action, upgradeDetailsNeedUpdate *bool) []fleetapi.Action {
	var actions []fleetapi.Action
	var upgradeAction fleetapi.Action
	for _, action := range input {
		if action.Type() == fleetapi.ActionTypeUpgrade {
			if upgradeAction == nil {
				upgradeAction = action
			} else {
				ad.log.Warnf("Found extra upgrade action in fleetgateway actions [id = %s]", action.ID())
				continue
			}
			if n := ad.queue.CancelType(fleetapi.ActionTypeUpgrade); n > 0 {
				ad.log.Debugw("New upgrade action retrieved from gateway, removing queued upgrade actions", "actions_found", n)
				// upgrade action(s) got removed from the queue so upgrade actions changed
				*upgradeDetailsNeedUpdate = true
			}
		}
		actions = append(actions, action)
	}

	return actions
}

// updateUpgradeDetails will construct the upgrade details based queue actions (assuming expired ones are still in the queue)
// and if ad.lastUpgradeDetails is different from the new upgrade details, it will update them.
func (ad *ActionDispatcher) updateUpgradeDetails(ts time.Time, detailsSetter details.Observer) {
	// no upgrade details from expired actions check the stored actions in the queue
	upgradeDetails := GetScheduledUpgradeDetails(ad.log, ad.queue.Actions(), ts)

	if ad.lastUpgradeDetailsIsSet && ad.lastUpgradeDetails.Equals(upgradeDetails) {
		// already the same details; do nothing
		return
	}
	ad.lastUpgradeDetailsIsSet = true
	ad.lastUpgradeDetails = upgradeDetails

	detailsSetter(upgradeDetails)
}

// scheduleRetry will schedule a retry for the passed action. Note that this adjusts the start time of the action
// but doesn't affect expiration time. If the action is scheduled to be retried and it is an upgrade action,
// upgradeDetailsNeedUpdate will be set to true.
func (ad *ActionDispatcher) scheduleRetry(ctx context.Context, action fleetapi.RetryableAction, acker acker.Acker, upgradeDetailsNeedUpdate *bool) {
	attempt := action.RetryAttempt()
	ad.log.Warnf("Re-scheduling action id %q of type %q, because it failed to dispatch with error: %+v", action.ID(), action.Type(), action.GetError())
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

	if action.Type() == fleetapi.ActionTypeUpgrade {
		*upgradeDetailsNeedUpdate = true
	}

	if err := acker.Ack(ctx, action); err != nil {
		ad.log.Errorf("Unable to ack action retry (id %s) to fleet-server: %v", action.ID(), err)
		return
	}
	if err := acker.Commit(ctx); err != nil {
		ad.log.Errorf("Unable to commit action retry (id %s) to fleet-server: %v", action.ID(), err)
	}
}

// GetScheduledUpgradeDetails returns the upgrade details of the next scheduled upgrade action, if any. It also adjusts
// accordingly the upgrade details if the action has expired.
func GetScheduledUpgradeDetails(log *logger.Logger, actions []fleetapi.ScheduledAction, ts time.Time) *details.Details {
	var nextUpgradeAction *fleetapi.ActionUpgrade
	var nextUpgradeStartTime time.Time
	var nextUpgradeExpirationTime time.Time

	for _, queuedAction := range actions {
		upgradeAction, ok := queuedAction.(*fleetapi.ActionUpgrade)
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
	// scheduled upgrade actions can have errors if retried
	if err := nextUpgradeAction.GetError(); err != nil {
		upgradeDetails.Metadata.ErrorMsg = fmt.Sprintf("A prior dispatch attempt failed with: %v", err)
	}
	return upgradeDetails
}
