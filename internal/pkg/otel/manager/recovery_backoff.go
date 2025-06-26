// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package manager

import (
	"time"

	"github.com/cenkalti/backoff/v5"
)

type recoveryBackoff struct {
	backoff *backoff.ExponentialBackOff
	timer   *time.Timer
	stopped bool
}

// newRecoveryBackoff returns a new recoveryBackoff
func newRecoveryBackoff(initialInterval time.Duration, maxInterval time.Duration) *recoveryBackoff {
	timer := time.NewTimer(time.Second)
	timer.Stop()

	return &recoveryBackoff{
		timer:   timer,
		stopped: true,
		backoff: &backoff.ExponentialBackOff{
			InitialInterval:     initialInterval,
			RandomizationFactor: backoff.DefaultRandomizationFactor,
			Multiplier:          backoff.DefaultMultiplier,
			MaxInterval:         maxInterval,
		},
	}
}

// IsStopped returns true if the timer is stopped
func (r *recoveryBackoff) IsStopped() bool {
	return r.stopped
}

// Stop stops the timer
func (r *recoveryBackoff) Stop() {
	r.timer.Stop()
	r.stopped = true
}

// ResetInitial resets the timer to the initial interval
func (r *recoveryBackoff) ResetInitial() {
	r.backoff.Reset()
	r.timer.Reset(r.backoff.InitialInterval)
	r.stopped = false
}

// C returns the timer channel
func (r *recoveryBackoff) C() <-chan time.Time {
	return r.timer.C
}

// ResetNext resets the timer to the next interval
func (r *recoveryBackoff) ResetNext() {
	r.timer.Reset(r.backoff.NextBackOff())
	r.stopped = false
}
