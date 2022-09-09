// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package dispatcher

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"time"

	"go.elastic.co/apm"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/pipeline/actions"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/internal/pkg/agent/storage/store"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

type priorityQueue interface {
	Add(fleetapi.Action, int64)
	DequeueActions() []fleetapi.Action
	Save() error
}

type actionHandlers map[string]actions.Handler

// ActionDispatcher processes actions coming from fleet using registered set of handlers.
type ActionDispatcher struct {
	ctx      context.Context
	log      *logger.Logger
	handlers actionHandlers
	def      actions.Handler
	queue    priorityQueue
}

// New creates a new action dispatcher.
func New(ctx context.Context, log *logger.Logger, def actions.Handler, queue priorityQueue) (*ActionDispatcher, error) {
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
		ctx:      ctx,
		log:      log,
		handlers: make(actionHandlers),
		def:      def,
		queue:    queue,
	}, nil
}

// Register registers a new handler for action.
func (ad *ActionDispatcher) Register(a fleetapi.Action, handler actions.Handler) error {
	k := ad.key(a)
	_, ok := ad.handlers[k]
	if ok {
		return fmt.Errorf("action with type %T is already registered", a)
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

func (ad *ActionDispatcher) key(a fleetapi.Action) string {
	return reflect.TypeOf(a).String()
}

// Dispatch dispatches an action using pre-registered set of handlers.
// ctx is used here ONLY to carry the span, for cancelation use the cancel
// function of the ActionDispatcher.ctx.
func (ad *ActionDispatcher) Dispatch(ctx context.Context, acker store.FleetAcker, actions ...fleetapi.Action) (err error) {
	span, ctx := apm.StartSpan(ctx, "dispatch", "app.internal")
	defer func() {
		apm.CaptureError(ctx, err).Send()
		span.End()
	}()

	// Creating a child context that carries both the ad.ctx cancelation and
	// the span from ctx.
	ctx, cancel := context.WithCancel(ad.ctx)
	defer cancel()
	ctx = apm.ContextWithSpan(ctx, span)

	actions = ad.queueScheduledActions(actions)
	actions = ad.dispatchCancelActions(actions, acker)
	queued, expired := ad.gatherQueuedActions(time.Now().UTC())
	ad.log.Debugf("Gathered %d actions from queue, %d actions expired", len(queued), len(expired))
	ad.log.Debugf("Expired actions: %v", expired)
	actions = append(actions, queued...)

	if err := ad.queue.Save(); err != nil {
		ad.log.Errorf("failed to persist action_queue: %v", err)
	}

	ad.log.Debugf(
		"Dispatch %d actions of types: %s",
		len(actions),
		strings.Join(detectTypes(actions), ", "),
	)

	if len(actions) == 0 {
		ad.log.Debug("No action to dispatch")
		return nil
	}

	for _, action := range actions {
		if err := ad.ctx.Err(); err != nil {
			return err
		}

		if err := ad.dispatchAction(action, acker); err != nil {
			ad.log.Debugf("Failed to dispatch action '%+v', error: %+v", action, err)
			return err
		}
		ad.log.Debugf("Successfully dispatched action: '%+v'", action)
	}

	return acker.Commit(ctx)
}

func (ad *ActionDispatcher) dispatchAction(a fleetapi.Action, acker store.FleetAcker) error {
	handler, found := ad.handlers[(ad.key(a))]
	if !found {
		return ad.def.Handle(ad.ctx, a, acker)
	}

	return handler.Handle(ad.ctx, a, acker)
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
		start, err := action.StartTime()
		if err == nil {
			ad.log.Debugf("Adding action id: %s to queue.", action.ID())
			ad.queue.Add(action, start.Unix())
			continue
		}
		if !errors.Is(err, fleetapi.ErrNoStartTime) {
			ad.log.Warnf("Issue gathering start time from action id %s: %v", action.ID(), err)
		}
		actions = append(actions, action)
	}
	return actions
}

// dispatchCancelActions will separate and dispatch any cancel actions from the actions list and return the rest of the list.
// cancel actions are dispatched seperatly as they may remove items from the queue.
func (ad *ActionDispatcher) dispatchCancelActions(actions []fleetapi.Action, acker store.FleetAcker) []fleetapi.Action {
	for i := len(actions) - 1; i >= 0; i-- {
		action := actions[i]
		// If it is a cancel action, remove from list and dispatch
		if action.Type() == fleetapi.ActionTypeCancel {
			actions = append(actions[:i], actions[i+1:]...)
			if err := ad.dispatchAction(action, acker); err != nil {
				ad.log.Errorf("Unable to dispatch cancel action: %v", err)
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
