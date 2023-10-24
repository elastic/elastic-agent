// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package lazy

import (
	"context"
	"net/http"

	"go.elastic.co/apm"

	"github.com/elastic/elastic-agent/internal/pkg/fleetapi"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

type batchAcker interface {
	AckBatch(ctx context.Context, actions []fleetapi.Action) (*fleetapi.AckResponse, error)
}

type retrier interface {
	Enqueue([]fleetapi.Action)
}

// Acker is a lazy acker which performs HTTP communication on commit.
type Acker struct {
	log     *logger.Logger
	acker   batchAcker
	queue   []fleetapi.Action
	retrier retrier
}

// Option Acker option function
type Option func(f *Acker)

// NewAcker creates a new lazy acker.
func NewAcker(baseAcker batchAcker, log *logger.Logger, opts ...Option) *Acker {
	f := &Acker{
		acker: baseAcker,
		queue: make([]fleetapi.Action, 0),
		log:   log,
	}

	for _, opt := range opts {
		opt(f)
	}

	return f
}

// WithRetrier option allows to specify the Retrier for acking
func WithRetrier(r retrier) Option {
	return func(f *Acker) {
		f.retrier = r
	}
}

// Ack acknowledges action.
func (f *Acker) Ack(ctx context.Context, action fleetapi.Action) (err error) {
	span, ctx := apm.StartSpan(ctx, "ack", "app.internal")
	defer func() {
		apm.CaptureError(ctx, err).Send()
		span.End()
	}()
	f.enqueue(action)
	return nil
}

// Commit commits ack actions.
func (f *Acker) Commit(ctx context.Context) (err error) {
	span, ctx := apm.StartSpan(ctx, "commit", "app.internal")
	defer func() {
		apm.CaptureError(ctx, err).Send()
		span.End()
	}()
	if len(f.queue) == 0 {
		return nil
	}

	actions := f.queue
	f.queue = make([]fleetapi.Action, 0)

	f.log.Debugf("lazy acker: ack batch: %s", actions)
	var resp *fleetapi.AckResponse
	resp, err = f.acker.AckBatch(ctx, actions)

	// If request failed enqueue all actions with retrier if it is set
	if err != nil {
		if f.retrier != nil {
			f.log.Warnf("lazy acker: failed ack batch, enqueue for retry: %s", actions)
			f.retrier.Enqueue(actions)
			return nil
		}
		f.log.Errorf("lazy acker: failed ack batch, no retrier set, fail with err: %s", err)
		return err
	}

	// If request succeeded check the errors on individual items
	if f.retrier != nil && resp != nil && resp.Errors {
		f.log.Error("lazy acker: partially failed ack batch")
		failed := make([]fleetapi.Action, 0)
		for i, res := range resp.Items {
			if res.Status >= http.StatusBadRequest {
				if i < len(actions) {
					failed = append(failed, actions[i])
				}
			}
		}
		if len(failed) > 0 {
			f.log.Infof("lazy acker: partially failed ack batch, enqueue for retry: %s", failed)
			f.retrier.Enqueue(failed)
		}
	}

	return nil
}

func (f *Acker) enqueue(action fleetapi.Action) {
	for _, a := range f.queue {
		if a.ID() == action.ID() {
			f.log.Debugf("action with id '%s' has already been queued", action.ID())
			return
		}
	}
	f.queue = append(f.queue, action)
	f.log.Debugf("appending action with id '%s' to the queue", action.ID())
}
