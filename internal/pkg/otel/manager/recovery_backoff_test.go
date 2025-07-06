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
	resetToInitial := 10 * time.Second
	recovery := newRecoveryBackoff(initialInterval, maxInterval, resetToInitial)
	recovery.backoff.RandomizationFactor = 0
	assert.True(t, recovery.stopped, "timer should be stopped when instantiated")

	delay := recovery.ResetInitial()
	assert.False(t, recovery.stopped, "timer should not be stopped")
	assert.Equal(t, initialInterval, delay, "timer reset duration should be the initial interval")

	delay = recovery.ResetNext()
	assert.False(t, recovery.stopped, "timer should not be stopped")
	assert.Greater(t, delay, initialInterval, "timer reset duration should be greater than the initial interval")
	assert.Less(t, delay, maxInterval, "timer reset duration should be less than the max interval")

	// wait for resetToInitial to check that ResetNext will reset to the initial backoff
	select {
	case <-time.After(resetToInitial + 2*time.Second):
		// add 2 extra seconds to account for jitter
	case <-t.Context().Done():
		t.Fatal("timed out waiting for resetToInitial")
	}

	delay = recovery.ResetNext()
	assert.False(t, recovery.stopped, "timer should not be stopped")
	assert.Equal(t, initialInterval, delay, "timer reset duration should be reset to the initial interval")

	recovery.Stop()
	assert.True(t, recovery.stopped, "timer should be stopped")
}
