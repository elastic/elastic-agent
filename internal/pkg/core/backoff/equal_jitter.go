// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package backoff

import (
	"math/rand"
	"time"
)

// EqualJitterBackoff implements an equal jitter strategy, meaning the wait time will consist of two parts,
// the first will be exponential and the other half will be random and will provide the jitter
// necessary to distribute the wait on remote endpoint.
type EqualJitterBackoff struct {
	duration time.Duration
	done     <-chan struct{}

	init     time.Duration
	max      time.Duration
	nextRand time.Duration

	last time.Time
}

// NewEqualJitterBackoff returns a new EqualJitter object.
func NewEqualJitterBackoff(done <-chan struct{}, init, max time.Duration) Backoff {
	return &EqualJitterBackoff{
		duration: init * 2, // Allow to sleep at least the init period on the first wait.
		done:     done,
		init:     init,
		max:      max,
		nextRand: time.Duration(rand.Int63n(int64(init))), //nolint:gosec
	}
}

// Reset resets the duration of the backoff.
func (b *EqualJitterBackoff) Reset() {
	// Allow to sleep at least the init period on the first wait.
	b.duration = b.init * 2
}

func (b *EqualJitterBackoff) NextWait() time.Duration {
	// Make sure we have always some minimal back off and jitter.
	temp := b.duration / 2
	return temp + b.nextRand
}

// Wait block until either the timer is completed or channel is done.
func (b *EqualJitterBackoff) Wait() bool {
	backoff := b.NextWait()

	// increase duration for next wait.
	b.nextRand = time.Duration(rand.Int63n(int64(b.duration)))
	b.duration *= 2
	if b.duration > b.max {
		b.duration = b.max
	}

	select {
	case <-b.done:
		return false
	case <-time.After(backoff):
		b.last = time.Now()
		return true
	}
}
