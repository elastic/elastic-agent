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
	"fmt"
	"time"

	"github.com/elastic/elastic-agent/internal/pkg/scheduler"
)

// Bucket is a Token Bucket for rate limiting
type Bucket struct {
	dropAmount int
	rateChan   chan struct{}
	closeChan  chan struct{}
	scheduler  scheduler.Scheduler
}

// NewTokenBucket creates a bucket and starts it.
// size: total size of the bucket
// dropAmount: amount which is dropped per every specified interval
// dropRate: specified interval when drop will happen
func NewTokenBucket(ctx context.Context, size, dropAmount int, dropRate time.Duration) (*Bucket, error) {
	s := scheduler.NewPeriodic(dropRate)
	return newTokenBucketWithScheduler(ctx, size, dropAmount, s)
}

func newTokenBucketWithScheduler(
	ctx context.Context,
	size, dropAmount int,
	s scheduler.Scheduler,
) (*Bucket, error) {
	if dropAmount > size {
		return nil, fmt.Errorf(
			"TokenBucket: invalid configuration, size '%d' is lower than drop amount '%d'",
			size,
			dropAmount,
		)
	}

	b := &Bucket{
		dropAmount: dropAmount,
		rateChan:   make(chan struct{}, size),
		closeChan:  make(chan struct{}),
		scheduler:  s,
	}
	go b.run(ctx)

	return b, nil
}

// Add adds item into a bucket. Add blocks until it is able to add item into a bucket.
func (b *Bucket) Add() {
	b.rateChan <- struct{}{}
}

// Close stops the rate limiting and does not let pass anything anymore.
func (b *Bucket) Close() {
	close(b.closeChan)
	close(b.rateChan)
	b.scheduler.Stop()
}

// run runs basic loop and consumes configured tokens per every configured period.
func (b *Bucket) run(ctx context.Context) {
	for {
		select {
		case <-b.scheduler.WaitTick():
			for i := 0; i < b.dropAmount; i++ {
				select {
				case <-b.rateChan:
				default: // do not cumulate drops
				}
			}
		case <-b.closeChan:
			return
		case <-ctx.Done():
			return
		}
	}
}
