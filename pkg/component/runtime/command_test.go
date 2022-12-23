// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package runtime

import (
	"context"
	"testing"
	"time"

	"github.com/elastic/elastic-agent/internal/pkg/tokenbucket"
	"github.com/stretchr/testify/require"
)

func TestAddToBucket(t *testing.T) {
	testCases := map[string]struct {
		bucketSize  int
		add         int
		addSleep    time.Duration
		shouldBlock bool
	}{
		"no error":           {1, 0, 10 * time.Millisecond, false},
		"error within limit": {1, 1, 10 * time.Millisecond, false},
		"errors > than limit but across timespans":                {1, 2, 800 * time.Millisecond, false},
		"errors > than limit within timespans, exact bucket size": {2, 2, 20 * time.Millisecond, false},
		"errors > than limit within timespans, off by one":        {2, 3, 20 * time.Millisecond, true},
		"errors > than limit within timespans":                    {2, 4, 20 * time.Millisecond, true},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			dropRate := 500 * time.Millisecond
			b, err := tokenbucket.NewTokenBucket(context.Background(), tc.bucketSize, tc.bucketSize, dropRate)
			require.NoError(t, err)

			blocked := false
			tryAddToBucket(b)
			<-time.After(dropRate + 200*time.Millisecond) // init ticker

			for i := 0; i < tc.add; i++ {
				blocked = blocked || tryAddToBucket(b)
				<-time.After(tc.addSleep)
			}
			b.Close()
			require.Equal(t, tc.shouldBlock, blocked)
		})
	}
}
