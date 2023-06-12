// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package broadcaster

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestSubscribersReceiveInitialValue(t *testing.T) {
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
