// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package backoff

import (
	"time"
)

// ExpBackoff exponential backoff, will wait an initial time and exponentially
// increases the wait time up to a predefined maximum. Resetting Backoff will reset the next sleep
// timer to the initial backoff duration.
type ExpBackoff struct {
	duration time.Duration
	done     <-chan struct{}

	init time.Duration
	max  time.Duration

	last time.Time
}

// NewExpBackoff returns a new exponential backoff.
func NewExpBackoff(done <-chan struct{}, init, max time.Duration) Backoff {
	return &ExpBackoff{
		duration: init,
		done:     done,
		init:     init,
		max:      max,
	}
}

// Reset resets the duration of the backoff.
func (b *ExpBackoff) Reset() {
	b.duration = b.init
}

func (b *ExpBackoff) NextWait() time.Duration {
	nextWait := b.duration
	nextWait *= 2
	if nextWait > b.max {
		nextWait = b.max
	}
	return nextWait
}

// Wait blocks until either the exponential backoff timer is completed or the
// done channel is closed.
// Wait returns true until done is closed. When done is closed, wait returns
// immediately, therefore callers should always check the return value.
func (b *ExpBackoff) Wait() bool {
	b.duration = b.NextWait()

	select {
	case <-b.done:
		return false
	case <-time.After(b.duration):
		b.last = time.Now()
		return true
	}
}
