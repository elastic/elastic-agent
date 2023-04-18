// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package fleet

import (
	"context"
	"time"
)

type debouncerFunc[T any] func(context.Context, <-chan T, time.Duration) <-chan T

func Debounce[T any](ctx context.Context, in <-chan T, minDebounce time.Duration) <-chan T {

	debounceTimer := time.NewTimer(minDebounce)
	cancelDebounceTimer := func() {
		if !debounceTimer.Stop() {
			<-debounceTimer.C
		}
	}

	return debounceWithTimeSource(ctx, in, debounceTimer.C, cancelDebounceTimer)
}

func debounceWithTimeSource[T any](ctx context.Context, in <-chan T, timeSrc <-chan time.Time, stopTimeSrc func()) <-chan T {
	outCh := make(chan T, 1)
	go func() {
		defer close(outCh)
		var (
			value              T
			receivedNewValue   bool
			minDebounceElapsed bool
		)

		for {
			select {
			case <-ctx.Done():
				// TODO: Should we return value when context expires?
				if receivedNewValue {
					outCh <- value
				}
				stopTimeSrc()
				return
			case newValue, ok := <-in:
				if !ok {
					// input channel has closed, set it to nil  so we don't unblock here anymore
					in = nil
					continue
				}
				receivedNewValue = true
				value = newValue
				if minDebounceElapsed {
					outCh <- value
					return
				}
			case <-timeSrc:
				minDebounceElapsed = true
				if receivedNewValue {
					outCh <- value
					return
				}
			}
		}
	}()

	return outCh
}
