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
	b := New(testValue, 32, 0)
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

	b := New(initialValue, valueCount, 0)
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

	b := New(initialValue, valueCount, 0)
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

	// Calling new instead of New so we can handle the run loop ourselves --
	// sending new values vs receiving from a subscriber is an inherent race
	// when the input channel is buffered (see the comments for New), so to
	// test Broadcaster's logic we need control of the order the messages
	// arrive in the run loop.
	b := new(initialValue, 16, valueCount)

	// Send a subscription request while running the Broadcaster loop so it
	// goes through
	var listenerChan chan int
	b.withOneIteration(func() {
		listenerChan = b.Subscribe(context.Background(), 0)
	})

	// Buffer all input values before starting the next iteration -- if
	// Broadcaster is working right, it will process all of these at the start
	// of the iteration before handling the subscriber read we're about to send.
	for i := 1; i <= valueCount; i++ {
		b.InputChan <- initialValue + i
	}

	// Confirm we can read the most recent value
	b.withOneIteration(func() {
		select {
		case value := <-listenerChan:
			require.Equal(t, initialValue+valueCount, value, "listener should receive the final value")
		case <-time.After(50 * time.Millisecond):
			require.Fail(t, "timed out waiting for listener channel")
		}
	})

	// Confirm the channel blocks after the first read (at least briefly)
	b.withOneIteration(func() {
		select {
		case value := <-listenerChan:
			require.Fail(t, fmt.Sprintf("received value %v when none was expected", value))
		case <-time.After(10 * time.Millisecond):
			b.Close() // Close the Broadcaster, which unblocks the run loop iteration
		}
	})
}

func TestBlockedSubscriberReceivesValueSequence(t *testing.T) {
	// Create a buffered subscriber, but send and receive values one at a time,
	// to make sure the value sequence is correct while actively reading.

	const valueCount = 32
	const initialValue = 4014

	b := New(initialValue, valueCount, 0)
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

	// Use a 0-length input buffer for this one, since reading immediately
	// after writing to a buffered channel would be a race in the test, but
	// when the input channel is unbuffered Broadcaster's spec claims
	// an immediate read will reflect exactly the latest values (see New).
	b := New(initialValue, 32, 0)
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
	b := new(0, 16, 0)
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

func TestGetReturnsLatestValue(t *testing.T) {
	// Check that Get always returns the latest value, even after Broadcaster
	// has shut down.
	const changeCount = 1000

	// Set an input buffer of 0 since we don't want any undelivered changes
	// when we call Get.
	curValue := 0
	b := New(curValue, 32, 0)
	for i := 0; i < changeCount; i++ {
		require.Equal(t, curValue, b.Get(), "Get should return the most recently set value")
		curValue++
		b.InputChan <- curValue
	}

	// Close the broadcaster and wait for its run loop to terminate
	b.Close()
	<-b.Done()

	require.Equal(t, curValue, b.Get(), "Closed Broadcaster should still return most recent value")
}

func TestSoftShutdownWaitsForSubscribers(t *testing.T) {
	// Buffer some values, close the input channel to initiate shutdown,
	// then make sure Broadcaster waits for its subscribers to catch up
	// before it stops.
	const initialValue = 4014
	const valueCount = 32

	b := New(initialValue, valueCount, 0)
	bufferedSub := b.Subscribe(context.Background(), valueCount)
	unbufferedSub := b.Subscribe(context.Background(), 0)

	for i := 1; i <= valueCount; i++ {
		b.InputChan <- initialValue + i
	}
	close(b.InputChan)

	// Wait briefly and make sure there was no shutdown
	select {
	case <-b.Done():
		require.Fail(t, "Broadcaster shouldn't shut down with 2 active subscribers")
	case <-time.After(10 * time.Millisecond):
	}

	// We shouldn't block for long, but if we do let's time out gracefully after 1s
	timeoutChan := time.After(5 * time.Second)
	for i := 0; i <= valueCount; i++ {
		select {
		case value := <-bufferedSub:
			assert.Equal(t, initialValue+i, value, "Expected value %d to be %d, got %d", i, initialValue+i, value)
		case <-timeoutChan:
			require.FailNow(t, "Timed out", "Expected %d values from buffered subscriber, got %d", valueCount+1, i)
		}
	}

	// Wait briefly and make sure there was still no shutdown
	select {
	case <-b.Done():
		require.Fail(t, "Broadcaster shouldn't shut down with 1 active subscriber")
	case <-time.After(10 * time.Millisecond):
	}

	// Read the final value on the unbuffered subscriber and verify that
	// Broadcaster finally shuts down
	select {
	case value := <-unbufferedSub:
		assert.Equal(t, initialValue+valueCount, value, "Unbuffered subscriber should only get final value of %d", initialValue+valueCount)
	case <-timeoutChan:
		require.FailNow(t, "Unbuffered subscriber received no values")
	}

	select {
	case <-b.Done():
	case <-timeoutChan:
		require.FailNow(t, "Subscribers completed but Broadcaster never shut down")
	}
}

func TestSubscribeAfterShutdown(t *testing.T) {
	// Create a Broadcaster, set one value, then close it and wait for shutdown.
	const finalValue = 4014

	b := New(0, 32, 0)
	b.InputChan <- finalValue
	b.Close()
	<-b.Done()

	// Add a new subscriber and check that it receives the final value followed
	// by a closed channel
	sub := b.Subscribe(context.Background(), 5)
	select {
	case value := <-sub:
		assert.Equal(t, finalValue, value, "Post-shutdown subscriber should receive the final value")
	case <-time.After(10 * time.Millisecond):
		assert.Fail(t, "Subscribers should always receive at least one value")
	}

	select {
	case value, ok := <-sub:
		if ok {
			assert.Fail(t, "Channel not closed", "Expected closed channel, got value %d", value)
		}
	case <-time.After(10 * time.Millisecond):
		assert.Fail(t, "Subscriber channel should be closed after reading final value")
	}
}

// withOneIteration runs a single iteration of Broadcaster's run loop in a
// background goroutine while running the given callback in the foreground.
// It then waits for the run loop iteration to finish, so additional
// iterations can be safely started as soon as the call returns.
// (This is for making test calls that require a blocking write into
// Broadcaster, e.g. Subscribe or Close.)
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
