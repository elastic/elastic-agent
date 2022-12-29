// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package runtime

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestAddToBucket(t *testing.T) {
	testCases := map[string]struct {
		bucketSize  int
		add         int
		addSleep    time.Duration
		shouldBlock bool
	}{
		"no error":           {1, 0, 1 * time.Millisecond, false},
		"error within limit": {1, 1, 1 * time.Millisecond, false},
		"errors > than limit but across timespans":                {1, 2, 80 * time.Millisecond, false},
		"errors > than limit within timespans, exact bucket size": {2, 2, 2 * time.Millisecond, false},
		"errors > than limit within timespans, off by one":        {2, 3, 2 * time.Millisecond, true},
		"errors > than limit within timespans":                    {2, 4, 2 * time.Millisecond, true},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			dropRate := 50 * time.Millisecond
			b := newRateLimiter(dropRate, tc.bucketSize)

			blocked := false
			b.Allow()
			<-time.After(dropRate + 20*time.Millisecond) // init ticker

			for i := 0; i < tc.add; i++ {
				wasBlocked := !b.Allow()
				blocked = blocked || wasBlocked
				<-time.After(tc.addSleep)
			}
			require.Equal(t, tc.shouldBlock, blocked)
		})
	}
}
