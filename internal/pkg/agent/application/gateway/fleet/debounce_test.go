// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package fleet

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDebouncer(t *testing.T) {

	t.Run("Debounce cancels without value when context expires", func(t *testing.T) {

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
		defer cancel()

		// unused input channel
		inCh := make(chan int)

		debounceDuration := 1 * time.Minute

		outCh := Debounce(ctx, inCh, debounceDuration)

		select {
		case val, ok := <-outCh:
			require.False(t, ok, "output channel didn't close as expected")
			assert.Zero(t, val)
		case <-time.After(100 * time.Millisecond):
			t.Fatal("debouncer didn't cancel in time when cancelling context")
		}

	})
	t.Run("Debounce cancels with value when context expires", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
		defer cancel()

		// input channel used to send a single value
		inCh := make(chan int)

		singleValue := 42
		// send a single value then close the input channel
		go func() {
			inCh <- singleValue
		}()

		debounceDuration := 1 * time.Minute

		outCh := Debounce(ctx, inCh, debounceDuration)

		select {
		case val, ok := <-outCh:
			require.True(t, ok, "output channel closed before sending value")
			assert.Equal(t, singleValue, val)
		case <-time.After(100 * time.Millisecond):
			t.Fatal("debouncer didn't cancel in time when cancelling context")
		}

		select {
		case val, ok := <-outCh:
			require.False(t, ok, "output channel didn't close as expected")
			assert.Zero(t, val)
		default:
			t.Fatal("debouncer didn't close the channel when cancelling context")
		}

	})

	t.Run("Simple debounce after initial duration", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()

		// setup an input channel where we inject a series of values very quickly
		inCh := make(chan int)

		debounceDuration := 50 * time.Millisecond
		maxValue := 10

		// insert values 1 <= v <= maxValue in the input channel
		go func() {
			for i := 0; i < maxValue; i++ {
				inCh <- i + 1
			}
		}()

		outCh := Debounce(ctx, inCh, debounceDuration)

		select {
		case val, ok := <-outCh:
			require.Truef(t, ok, "output channel closed unexpectedly")
			assert.Equal(t, maxValue, val)
		case <-ctx.Done():
			t.Fatal("didn't receive a value before timeout")
		}

		select {
		case val, ok := <-outCh:
			require.False(t, ok, "output channel didn't close as expected")
			assert.Zero(t, val)
		default:
			t.Fatal("debouncer didn't close the channel after the initial debounce duration")
		}

	})

	t.Run("Simple debounce when value comes after minDuration", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		defer cancel()

		// setup an input channel where we inject a value
		inCh := make(chan int)

		debounceDuration := 10 * time.Millisecond
		singleValue := 42
		// insert values 1 <= v <= maxValue in the input channel
		go func() {
			<-time.After(100 * time.Millisecond)
			inCh <- singleValue
		}()

		outCh := Debounce(ctx, inCh, debounceDuration)

		select {
		case val, ok := <-outCh:
			require.Truef(t, ok, "output channel closed unexpectedly")
			assert.Equal(t, singleValue, val)
		case <-ctx.Done():
			t.Fatal("didn't receive a value before timeout")
		}

		select {
		case val, ok := <-outCh:
			require.False(t, ok, "output channel didn't close as expected")
			assert.Zero(t, val)
		default:
			t.Fatal("debouncer didn't close the channel after the debounce")
		}

	})

	t.Run("Send value when input channel closed after first value", func(t *testing.T) {

		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()

		// setup an input channel where we inject a single value before closing
		inCh := make(chan int)

		// debounce duration is still within the context timeout but value should return after the channel closure, after the debounce
		debounceDuration := 50 * time.Millisecond
		singleValue := 1

		// send a single value then close the input channel
		go func() {
			inCh <- singleValue
			close(inCh)
		}()

		outCh := Debounce(ctx, inCh, debounceDuration)

		select {
		case val, ok := <-outCh:
			require.Truef(t, ok, "channel closed before we receive the value")
			assert.Equal(t, singleValue, val)

		case <-ctx.Done():
			t.Fatal("didn't receive a value before timeout")
		}

		select {
		case val, ok := <-outCh:
			assert.Falsef(t, ok, "channel should be closed after the single value")
			assert.Zero(t, val)
		default:
			t.Fatal("debouncer didn't close the output channel in time")
		}

	})
}
