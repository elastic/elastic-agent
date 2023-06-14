// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package broadcaster

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSubscriberReceivesInitialValue(t *testing.T) {
	// Create a Broadcaster with an initial value but no additional values,
	// and make sure a new subscriber can immediately read it.

	const testValue = 4014
	b := New(testValue, 32)
	listenerChan := b.Subscribe(context.Background(), 0)

	select {
	case value := <-listenerChan:
		assert.Equal(t, testValue, value, "reported value doesn't match initial value")
	case <-time.After(50 * time.Millisecond):
		// This should be an immediate synchronous read, so the timeout is short.
		assert.Fail(t, "new subscriber received no value on its listener channel")
	}
}

func TestSubscriberReceivesValueSequence(t *testing.T) {
	// Create a Broadcaster and subscriber with a buffer length of 32 and send
	// 32 changes through it, then verify that the subscriber receives them all
	// in order.

	const valueCount = 32
	const initialValue = 4014

	b := New(initialValue, valueCount)
	listenerChan := b.Subscribe(context.Background(), valueCount)

	for i := 1; i <= valueCount; i++ {
		b.InputChan <- initialValue + i
	}

	timeoutChan := time.After(5 * time.Second)
	// We should be able to read all the changes plus the initial value.
	for i := 0; i <= valueCount; i++ {
		expected := initialValue + i
		select {
		case value := <-listenerChan:
			require.Equal(t, expected, value, "listener should read the same value sequence that was written")
		case <-timeoutChan:
			require.Failf(t, "timeout waiting for expected values", "next expected value: %v", expected)
		}
	}
}

func TestMultipleSubscribersReceiveValueSequence(t *testing.T) {
	// Create a Broadcaster and 3 subscribers with a buffer length of 32 and send
	// 32 changes through it, then verify that each subscriber receives them all
	// in order.

	const subscriberCount = 3
	const valueCount = 32
	const initialValue = 4014

	b := New(initialValue, valueCount)
	defer b.Close()
	subscribers := []chan int{}
	for i := 0; i < subscriberCount; i++ {
		subscribers = append(subscribers,
			b.Subscribe(context.Background(), valueCount))
	}

	for i := 1; i <= valueCount; i++ {
		b.InputChan <- initialValue + i
	}

	timeoutChan := time.After(5 * time.Second)
	for sIndex, subscriber := range subscribers {
		// We should be able to read all the changes plus the initial value.
		for i := 0; i <= valueCount; i++ {
			expected := initialValue + i
			select {
			case value := <-subscriber:
				require.Equal(t, expected, value,
					"listener %d at index %d should read the same value sequence that was written",
					sIndex, i)
			case <-timeoutChan:
				require.Failf(t, "timeout waiting for expected values", "next expected value: %v", expected)
			}
		}
	}
}

func TestUnbufferedSubscriberReceivesMostRecentValue(t *testing.T) {
	// Send 32 values on a Broadcaster with a buffer length of 16, then confirm
	// that an unbuffered subscriber (bufferLen 0) receives only the most recent
	// change.

	const valueCount = 32
	const initialValue = 4014

	b := New(initialValue, 16)
	listenerChan := b.Subscribe(context.Background(), 0)

	for i := 1; i <= valueCount; i++ {
		b.InputChan <- initialValue + i
	}

	// Confirm we can read the most recent value
	select {
	case value := <-listenerChan:
		require.Equal(t, initialValue+valueCount, value, "listener should receive the final value")
	case <-time.After(50 * time.Millisecond):
		require.Fail(t, "timed out waiting for listener channel")
	}

	// Confirm the channel blocks after the first read (at least briefly)
	select {
	case value := <-listenerChan:
		require.Fail(t, fmt.Sprintf("received value %v when none was expected", value))
	case <-time.After(10 * time.Millisecond):
	}
}

func TestBlockedSubscriberReceivesValueSequence(t *testing.T) {
	// Create a buffered subscriber, but send and receive values one at a time,
	// to make sure the value sequence is correct while actively reading.

	const valueCount = 32
	const initialValue = 4014

	b := New(initialValue, valueCount)
	listenerChan := b.Subscribe(context.Background(), valueCount)
	timeoutChan := time.After(5 * time.Second)

	// Start by reading the initial value, which should always be possible.
	select {
	case value := <-listenerChan:
		require.Equal(t, initialValue, value, "initial value should match Broadcaster initialization")
	case <-timeoutChan:
		require.FailNow(t, "timeout waiting for initial read")
	}
	// For each additional value, confirm that the read channel is blocked
	// initially then unblocks when we send the value, and that the sent and
	// received values match.
	for i := 1; i <= valueCount; i++ {
		// confirm that a read blocks (at least briefly) since there are no additional
		// values available.
		select {
		case value := <-listenerChan:
			require.FailNow(t, fmt.Sprintf("received value %v when none was expected", value))
		case <-time.After(5 * time.Millisecond):
		}

		expected := initialValue + i
		b.InputChan <- expected
		select {
		case value := <-listenerChan:
			require.Equal(t, expected, value, "listener value should match what was written")
		case <-timeoutChan:
			require.FailNow(t, "timeout waiting for initial read")
		}
	}
}

func TestSubscriberSkipsOldestValuesWhenBufferExceeded(t *testing.T) {
	// Send 32 changes on a Broadcaster with a buffer of 32, then confirm that
	// a subscriber with a buffer of 16 skips the first 16 values.

	const initialValue = 4014

	b := New(initialValue, 32)
	listenerChan := b.Subscribe(context.Background(), 16)

	for i := 1; i <= 32; i++ {
		b.InputChan <- initialValue + i
	}

	timeoutChan := time.After(5 * time.Second)
	for i := 0; i <= 16; i++ {
		// add 16 to expected because that's how many values the listener
		// should have skipped
		expected := initialValue + 16 + i
		select {
		case value := <-listenerChan:
			require.Equal(t, expected, value, "listener should read the same value sequence that was written")
		case <-timeoutChan:
			require.Failf(t, "timeout waiting for expected values", "next expected value: %v", expected)
		}
	}
}

func TestCancelledContextClosesSubscriberChannel(t *testing.T) {
	// Create a new buffered subscriber, immediately cancel the context, and
	// confirm the channel is closed without receiving any values.
	// We test synchronously one iteration at a time, because otherwise
	// there's an unavoidable race if the context signal and the channel
	// read both arrive at the same time.
	b := new(0, 16)
	ctx, cancel := context.WithCancel(context.Background())
	var listenerChan chan int

	// Iterate to detect the subscription (in a helper to run the iteration
	// in the background, since we're making a blocking call to its API).
	b.withOneIteration(func() {
		listenerChan = b.Subscribe(ctx, 16)
	})

	// Cancel context then iterate again to detect the cancellation
	cancel()
	b.runLoopIterate()

	// Verify the channel was closed with no values
	select {
	case _, ok := <-listenerChan:
		assert.False(t, ok, "channel should have closed after context cancellation")
	case <-time.After(time.Second):
		assert.Fail(t, "timeout waiting for channel to close after context cancellation")
	}
}

// withOneIteration runs a single iteration of Broadcaster's run loop in a
// background goroutine while running the given callback in the foreground.
// It then waits for the run loop iteration to finish, so additional
// iterations can be safely started as soon as the call returns.
func (b *Broadcaster[T]) withOneIteration(callback func()) {
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		b.runLoopIterate()
		wg.Done()
	}()
	callback()
	wg.Wait()
}
