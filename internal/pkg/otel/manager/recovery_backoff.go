// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package manager

import (
	"time"

	"github.com/cenkalti/backoff/v5"
)

type recoveryBackoff struct {
	backoff        *backoff.ExponentialBackOff
	timer          *time.Timer
	prevReset      time.Time
	resetToInitial time.Duration
	stopped        bool
}

// newRecoveryBackoff returns a new recoveryBackoff.
//   - initialInterval: the initial backoff interval
//   - maxInterval: the maximum backoff interval
//   - resetToInitial: the duration after which ResetNext will reset to the initial backoff interval
//     (if set to 0, the timer will never be reset to the initial interval)
func newRecoveryBackoff(
	initialInterval time.Duration,
	maxInterval time.Duration,
	resetToInitial time.Duration,
) *recoveryBackoff {
	timer := time.NewTimer(time.Second)
	timer.Stop()

	return &recoveryBackoff{
		timer:          timer,
		stopped:        true,
		resetToInitial: resetToInitial,
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

// ResetInitial resets the timer to the initial interval and returns the duration that the timer was reset to
func (r *recoveryBackoff) ResetInitial() time.Duration {
	r.backoff.Reset()
	delay := r.backoff.NextBackOff()
	r.timer.Reset(delay)
	r.prevReset = time.Now()
	r.stopped = false
	return delay
}

// C returns the timer channel
func (r *recoveryBackoff) C() <-chan time.Time {
	return r.timer.C
}

// ResetNext resets the timer to the next backoff interval and returns the duration that the timer was reset to.
// Note that this will reset to the initial interval if resetToInitial is set and the time since the previous
// ResetNext exceeds it.
func (r *recoveryBackoff) ResetNext() time.Duration {
	if r.resetToInitial != 0 && time.Now().After(r.prevReset.Add(r.resetToInitial)) {
		// resetToInitial is set and the time since the last reset exceeds resetToInitial,
		// so reset the backoff to the initial interval
		return r.ResetInitial()
	}

	r.prevReset = time.Now()
	delay := r.backoff.NextBackOff()
	r.timer.Reset(delay)
	return delay
}
