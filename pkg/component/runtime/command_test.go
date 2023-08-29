// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package runtime

import (
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestAddToBucket(t *testing.T) {
	testCases := map[string]struct {
		bucketSize int
		dropRate   time.Duration
		add        int
		// Warning: this sleep duration is not very precise on Windows machines as the system clock ticks only every 15ms
		addSleep    time.Duration
		shouldBlock bool
	}{
		"no error":           {1, 50 * time.Millisecond, 0, 1 * time.Millisecond, false},
		"error within limit": {1, 50 * time.Millisecond, 1, 1 * time.Millisecond, false},
		"errors > than limit but across timespans":                {1, 50 * time.Millisecond, 2, 80 * time.Millisecond, false},
		"errors > than limit within timespans, exact bucket size": {2, 50 * time.Millisecond, 2, 2 * time.Millisecond, false},
		// These testcases use a longer duration as dropRate to make sure that on Windows machine we don't drop any old events
		"errors > than limit within timespans, off by one": {2, 150 * time.Millisecond, 3, 2 * time.Millisecond, true},
		"errors > than limit within timespans":             {2, 150 * time.Millisecond, 4, 2 * time.Millisecond, true},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			if runtime.GOOS == "windows" {
				t.Skip("https://github.com/elastic/elastic-agent/issues/3290: Flaky timing on Windows")
			}
			b := newRateLimiter(tc.dropRate, tc.bucketSize)

			blocked := false
			b.Allow()
			<-time.After(tc.dropRate + 20*time.Millisecond) // init ticker

			for i := 0; i < tc.add; i++ {
				t.Logf("%v : add 1 element when there are %f tokens available", time.Now(), b.Tokens())
				wasBlocked := !b.Allow()
				blocked = blocked || wasBlocked
				<-time.After(tc.addSleep)
			}
			require.Equal(t, tc.shouldBlock, blocked)
		})
	}
}
