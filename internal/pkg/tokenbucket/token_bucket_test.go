// Licensed to Elasticsearch B.V. under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Elasticsearch B.V. licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package tokenbucket

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/elastic/elastic-agent/internal/pkg/scheduler"
)

func TestTokenBucket(t *testing.T) {
	dropAmount := 1
	bucketSize := 3

	t.Run("when way below the bucket size it should not block", func(t *testing.T) {
		stepper := scheduler.NewStepper()

		b, err := newTokenBucketWithScheduler(
			context.Background(),
			bucketSize,
			dropAmount,
			stepper,
		)

		assert.NoError(t, err, "initiating a bucket failed")

		// Below the bucket size and should not block.
		b.Add()
	})

	t.Run("when below the bucket size it should not block", func(t *testing.T) {
		stepper := scheduler.NewStepper()

		b, err := newTokenBucketWithScheduler(
			context.Background(),
			bucketSize,
			dropAmount,
			stepper,
		)

		assert.NoError(t, err, "initiating a bucket failed")

		// Below the bucket size and should not block.
		b.Add()
		b.Add()
	})

	t.Run("when we hit the bucket size it should block", func(t *testing.T) {
		stepper := scheduler.NewStepper()

		b, err := newTokenBucketWithScheduler(
			context.Background(),
			bucketSize,
			dropAmount,
			stepper,
		)

		assert.NoError(t, err, "initiating a bucket failed")

		// Same as the bucket size and should block.
		b.Add()
		b.Add()
		b.Add()

		// Out of bound unblock calls
		unblock := func() {
			var wg sync.WaitGroup
			wg.Add(1)
			go func(wg *sync.WaitGroup) {
				wg.Done()

				// will unblock the next Add after a second.
				<-time.After(1 * time.Second)
				stepper.Next()
			}(&wg)
			wg.Wait()
		}

		unblock()
		b.Add() // Should block and be unblocked, if not unblock test will timeout.
		unblock()
		b.Add() // Should block and be unblocked, if not unblock test will timeout.
	})

	t.Run("When we use a timer scheduler we can unblock", func(t *testing.T) {
		d := 1 * time.Second
		b, err := NewTokenBucket(
			context.Background(),
			bucketSize,
			dropAmount,
			d,
		)

		assert.NoError(t, err, "initiating a bucket failed")

		// Same as the bucket size and should block.
		b.Add()
		b.Add()
		b.Add()
		b.Add() // Should block and be unblocked, if not unblock test will timeout.
	})
}
