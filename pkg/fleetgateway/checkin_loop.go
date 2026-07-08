// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

// Package fleetgateway provides a shared checkin loop for Fleet Server clients.
package fleetgateway

import (
	"context"
	"time"

	"github.com/elastic/elastic-agent/pkg/backoff"
	"github.com/elastic/elastic-agent/pkg/scheduler"
)

const (
	// DefaultInitBackoff is the default initial backoff duration for the checkin retry loop.
	DefaultInitBackoff = 60 * time.Second

	// DefaultMaxBackoff is the default maximum backoff duration for the checkin retry loop.
	DefaultMaxBackoff = 10 * time.Minute

	// DefaultCheckinDuration is the default duration between successful checkins.
	DefaultCheckinDuration = 1 * time.Second

	// DefaultCheckinJitter is the default jitter applied to the checkin interval.
	DefaultCheckinJitter = 500 * time.Millisecond

	// ErrConsecutiveUnauthBackoff is the scheduler interval applied after too many consecutive 401 errors.
	ErrConsecutiveUnauthBackoff = time.Hour

	maxUnauthCounter = 6
)

// ExecuteFunc performs a single checkin attempt.
// If nextInterval > 0, the scheduler will use it as the duration until the next tick.
// unauthenticated must be true when the error is a 401 / invalid-API-key failure so the
// loop can apply 401 escalation without treating the error as a transient retry candidate.
type ExecuteFunc func(ctx context.Context) (nextInterval time.Duration, unauthenticated bool, err error)

// CheckinLoop drives a tick-based checkin retry loop with backoff and 401 escalation.
// On each scheduler tick it calls execute; on transient failure it backs off using bo.
// After maxUnauthCounter (6) consecutive 401 errors it extends the tick interval to
// ErrConsecutiveUnauthBackoff (1 hour) to avoid hammering Fleet Server with an invalid key.
type CheckinLoop struct {
	sched scheduler.Scheduler
	bo    backoff.Backoff
}

// New creates a CheckinLoop driven by sched and retried with bo.
func New(sched scheduler.Scheduler, bo backoff.Backoff) *CheckinLoop {
	return &CheckinLoop{sched: sched, bo: bo}
}

// Run drives the checkin loop until ctx is cancelled.
// It returns ctx.Err() when the context is done.
func (c *CheckinLoop) Run(ctx context.Context, execute ExecuteFunc) error {
	unauthCounter := 0

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-c.sched.WaitTick():
		}

		c.bo.Reset()
		for ctx.Err() == nil {
			nextInterval, unauth, err := execute(ctx)
			if err == nil {
				unauthCounter = 0
				if nextInterval > 0 {
					c.sched.SetDuration(nextInterval)
				}
				break
			}

			if unauth {
				unauthCounter++
				if unauthCounter > maxUnauthCounter {
					c.sched.SetDuration(ErrConsecutiveUnauthBackoff)
					unauthCounter = 0
				}
				break // 401s are not retried with backoff; wait for the next scheduled tick
			}

			if !c.bo.Wait() {
				return ctx.Err()
			}
		}
	}
}
