// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package manager

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestRecoveryBackoff(t *testing.T) {
	initialInterval := 100 * time.Nanosecond
	maxInterval := 1 * time.Second
	resetToInitial := 5 * time.Second
	recovery := newRecoveryBackoff(initialInterval, maxInterval, resetToInitial)
	recovery.backoff.RandomizationFactor = 0
	assert.True(t, recovery.stopped, "timer should be stopped when instantiated")

	resetTime := time.Now()
	recovery.ResetInitial()
	assert.False(t, recovery.stopped, "timer should not be stopped")
	assert.True(t, resetTime.Before(recovery.prevReset), "resetTime should be before prevReset")

	resetTime = time.Now()
	recovery.ResetNext()
	assert.False(t, recovery.stopped, "timer should not be stopped")
	assert.True(t, resetTime.Before(recovery.prevReset), "resetTime should be before prevReset")
	nextBackoffWithoutReset := recovery.backoff.NextBackOff()

	// wait for resetToInitial to check that ResetNext will reset to the initial backoff
	select {
	case <-time.After(resetToInitial + 2*time.Second):
	case <-t.Context().Done():
		t.Fatal("timed out waiting for resetToInitial")
	}

	recovery.ResetNext()
	assert.False(t, recovery.stopped, "timer should not be stopped")
	assert.True(t, resetTime.Before(recovery.prevReset), "resetTime should be before prevReset")
	assert.Less(t, recovery.backoff.NextBackOff(), nextBackoffWithoutReset, "next backoff should be less than backoff without reset")

	recovery.Stop()
	assert.True(t, recovery.stopped, "timer should be stopped")
}
