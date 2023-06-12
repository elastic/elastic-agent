// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package broadcaster

import (
	"context"
	"fmt"
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
			require.Failf(t, "timeout waiting for expected values", "next expected value: %v", i)
		}
	}
}

func TestBlockedSubscriberReceivesUpdates(t *testing.T) {
	// Create a buffered subscriber, but send and receive values one at a time,
	// to make sure the value sequence is correct while actively reading.

	const valueCount = 32
	const initialValue = 4014

	b := New(initialValue, valueCount)
	listenerChan := b.Subscribe(context.Background(), valueCount)

	timeoutChan := time.After(5 * time.Second)
	select {
	case value := <-listenerChan:
		require.Equal(t, initialValue, value, "initial value should match Broadcaster initialization")
	case <-timeoutChan:
		require.FailNow(t, "timeout waiting for initial read")
	}
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
