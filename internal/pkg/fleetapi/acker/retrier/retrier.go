// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package retrier

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/elastic/elastic-agent/internal/pkg/core/backoff"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

const (
	defaultMaxRetries = 5

	defaultInitialRetryInterval = 1 * time.Minute
	defaultMaxRetryInterval     = 5 * time.Minute
)

// BatchAcker provider interface, implemented by fleet acker
type BatchAcker interface {
	AckBatch(ctx context.Context, actions []fleetapi.Action) (*fleetapi.AckResponse, error)
}

// Option Retrier option function
type Option func(*Retrier)

// Retrier implements retrier for actions acks
type Retrier struct {
	acker BatchAcker // AckBatch provider
	log   *logger.Logger

	doneCh chan struct{} // signal channel to kickoff retry loop if not running
	kickCh chan struct{} // signal channel when retry loop is done

	actions []fleetapi.Action // pending actions

	maxRetryInterval     time.Duration // max retry interval
	maxRetries           int           // configurable maxNumber of retries per action
	initialRetryInterval time.Duration // initial retry interval

	mx sync.Mutex
}

// New creates new instance of retrier
func New(acker BatchAcker, log *logger.Logger, opts ...Option) *Retrier {
	r := &Retrier{
		acker:                acker,
		log:                  log,
		initialRetryInterval: defaultInitialRetryInterval,
		maxRetryInterval:     defaultMaxRetryInterval,
		maxRetries:           defaultMaxRetries,
		kickCh:               make(chan struct{}, 1),
		doneCh:               make(chan struct{}, 1),
	}
	for _, opt := range opts {
		opt(r)
	}
	return r
}

// WithInitialRetryInterval configures retrier with initial retry delay provided
func WithInitialRetryInterval(dur time.Duration) Option {
	return func(f *Retrier) {
		f.initialRetryInterval = dur
	}
}

// WithMaxRetryInterval configures retrier with max retry interval provided
func WithMaxRetryInterval(dur time.Duration) Option {
	return func(f *Retrier) {
		f.maxRetryInterval = dur
	}
}

// WithMaxAckRetries configures max retries provided
// The number of retries left is tracked per action
func WithMaxAckRetries(maxRetries int) Option {
	return func(f *Retrier) {
		f.maxRetries = maxRetries
	}
}

// Done signals when retry loop is done, useful for testing
func (r *Retrier) Done() <-chan struct{} {
	return r.doneCh
}

// Run runs retrier loop
func (r *Retrier) Run(ctx context.Context) {
	for {
		select {
		case <-r.kickCh:
			r.runRetries(ctx)
		case <-ctx.Done():
			r.log.Debugf("ack retrier: exit on %v", ctx.Err())
			return
		}
	}
}

// Enqueue enqueue provided actions for the next retry
func (r *Retrier) Enqueue(actions []fleetapi.Action) {
	if len(actions) == 0 {
		return
	}

	r.mx.Lock()
	r.actions = append(r.actions, actions...)
	r.mx.Unlock()

	// Signal to kick off retry loop, non blocking if the signal is already pending
	select {
	case r.kickCh <- struct{}{}:
	default:
	}
}

func (r *Retrier) runRetries(ctx context.Context) {
	r.log.Debug("ack retrier: enter retry loop")

	// Map tracking the number of retries per action, where the key is action ID and the value is the number of retries left per action
	retries := make(map[string]int)

	b := backoff.NewEqualJitterBackoff(ctx.Done(), r.initialRetryInterval, r.maxRetryInterval)

	for i := 0; b.Wait(); i++ {
		r.mx.Lock()
		actions := r.actions
		r.actions = nil
		r.mx.Unlock()

		var failed []fleetapi.Action
		r.log.Debug("ack retrier: before AckBatch")
		resp, err := r.acker.AckBatch(ctx, actions)
		r.log.Debugf("ack retrier: after AckBatch: %#v, %#v", resp, err)
		if err != nil {
			r.log.Errorf("ack retrier: commit failed with error: %v", err)
			// Commit failed, update retry map from actions
			failed = r.updateRetriesMap(retries, actions, nil)
		} else if resp != nil && resp.Errors {
			// Commit partially failed, update retry map from failed actions
			failed = r.updateRetriesMap(retries, actions, resp)
			r.log.Debugf("ack retrier: commit partially failed: %#v", failed)
		}

		r.log.Debugf("ack retrier: failed actions: %#v", failed)
		// Combine actions for the next retry
		r.mx.Lock()
		if len(r.actions) > 0 {
			r.log.Debug("ack retrier: reset timer")
			b.Reset() // reset backoff if new actions came while committing
		}
		r.actions = append(failed, r.actions...)
		r.log.Debugf("ack retrier: total actions: %#v", r.actions)
		exit := (len(r.actions) == 0)

		r.mx.Unlock()

		r.log.Debugf("ack retrier: exit: %v", exit)
		if exit {
			break
		}
	}
	// Signal loop is done
	select {
	case r.doneCh <- struct{}{}:
	default:
	}
	r.log.Debug("ack retrier: exit retry loop")
}

func (r *Retrier) updateRetriesMap(retries map[string]int, actions []fleetapi.Action, resp *fleetapi.AckResponse) (failed []fleetapi.Action) {
	isFailed := func(pos int) bool {
		// Response is nil when all actions fail, still need to update attempts bookkeeping
		if resp == nil {
			return true
		}
		if pos >= len(resp.Items) {
			return true
		}
		return (resp.Items[pos].Status >= http.StatusBadRequest)
	}

	for i, action := range actions {
		if isFailed(i) {
			n, ok := retries[action.ID()]
			if !ok {
				n = r.maxRetries
			}
			n--
			if n > 0 {
				retries[action.ID()] = n
				failed = append(failed, action)
			} else {
				delete(retries, action.ID())
			}
		} else {
			delete(retries, action.ID())
		}
	}

	return failed
}
