// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package backoff

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

type factory func(<-chan struct{}) Backoff

func TestCloseChannel(t *testing.T) {
	init := 2 * time.Millisecond
	max := 5 * time.Second

	tests := map[string]factory{
		"ExpBackoff": func(done <-chan struct{}) Backoff {
			return NewExpBackoff(done, init, max)
		},
		"EqualJitterBackoff": func(done <-chan struct{}) Backoff {
			return NewEqualJitterBackoff(done, init, max)
		},
	}

	for name, f := range tests {
		t.Run(name, func(t *testing.T) {
			c := make(chan struct{})
			b := f(c)
			close(c)
			assert.False(t, b.Wait())
		})
	}
}

func TestUnblockAfterInit(t *testing.T) {
	init := 1 * time.Millisecond
	max := 5 * time.Second

	tests := map[string]factory{
		"ExpBackoff": func(done <-chan struct{}) Backoff {
			return NewExpBackoff(done, init, max)
		},
		"EqualJitterBackoff": func(done <-chan struct{}) Backoff {
			return NewEqualJitterBackoff(done, init, max)
		},
	}

	for name, f := range tests {
		t.Run(name, func(t *testing.T) {
			c := make(chan struct{})
			defer close(c)

			b := f(c)

			startedAt := time.Now()
			assert.True(t, WaitOnError(b, errors.New("bad bad")))
			assert.True(t, time.Now().Sub(startedAt) >= init)
		})
	}
}

func TestNextWait(t *testing.T) {
	init := time.Millisecond
	max := 5 * time.Second

	tests := map[string]factory{
		"ExpBackoff": func(done <-chan struct{}) Backoff {
			return NewExpBackoff(done, init, max)
		},
		"EqualJitterBackoff": func(done <-chan struct{}) Backoff {
			return NewEqualJitterBackoff(done, init, max)
		},
	}

	for name, f := range tests {
		t.Run(name, func(t *testing.T) {
			c := make(chan struct{})
			b := f(c)

			startWait := b.NextWait()
			assert.Equal(t, startWait, b.NextWait(), "next wait not stable")

			startedAt := time.Now()
			b.Wait()
			waitDuration := time.Now().Sub(startedAt)
			nextWait := b.NextWait()

			t.Logf("actualWait: %s startWait: %s nextWait: %s", waitDuration, startWait, nextWait)
			assert.Less(t, startWait, nextWait, "wait value did not increase")
			assert.GreaterOrEqual(t, waitDuration, startWait, "next wait duration <= actual wait duration")
		})
	}
}
