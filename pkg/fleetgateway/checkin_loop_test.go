// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package fleetgateway_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/elastic/elastic-agent/pkg/backoff"
	"github.com/elastic/elastic-agent/pkg/fleetgateway"
	"github.com/elastic/elastic-agent/pkg/scheduler"
)

// immediateBackoff is a Backoff that never sleeps.
type immediateBackoff struct{ waited int }

func (b *immediateBackoff) Wait() bool              { b.waited++; return true }
func (b *immediateBackoff) NextWait() time.Duration { return 0 }
func (b *immediateBackoff) Reset()                  {}

var _ backoff.Backoff = (*immediateBackoff)(nil)

// trackedScheduler embeds Stepper and records SetDuration calls.
type trackedScheduler struct {
	*scheduler.Stepper
	durations []time.Duration
}

func (s *trackedScheduler) SetDuration(d time.Duration) { s.durations = append(s.durations, d) }

func newTracked() *trackedScheduler {
	return &trackedScheduler{Stepper: scheduler.NewStepper()}
}

// runLoop starts loop.Run in a goroutine and returns the done channel.
func runLoop(ctx context.Context, loop *fleetgateway.CheckinLoop, fn fleetgateway.ExecuteFunc) <-chan error {
	ch := make(chan error, 1)
	go func() { ch <- loop.Run(ctx, fn) }()
	return ch
}

// TestCheckinLoop_SuccessOnFirstAttempt checks that a successful execute doesn't invoke backoff.
func TestCheckinLoop_SuccessOnFirstAttempt(t *testing.T) {
	sched := newTracked()
	bo := &immediateBackoff{}
	loop := fleetgateway.New(sched, bo)
	ctx, cancel := context.WithCancel(context.Background())

	calls := 0
	done := runLoop(ctx, loop, func(_ context.Context) (time.Duration, bool, error) {
		calls++
		if calls >= 2 {
			cancel()
		}
		return 0, false, nil
	})

	sched.Next()
	sched.Next()

	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("Run returned %v, want context.Canceled", err)
	}
	if bo.waited != 0 {
		t.Errorf("backoff.Wait called %d times on success, want 0", bo.waited)
	}
}

// TestCheckinLoop_RetryOnTransientError checks that transient errors trigger backoff retries.
func TestCheckinLoop_RetryOnTransientError(t *testing.T) {
	sched := newTracked()
	bo := &immediateBackoff{}
	loop := fleetgateway.New(sched, bo)
	ctx, cancel := context.WithCancel(context.Background())
	errTransient := errors.New("transient")

	calls := 0
	done := runLoop(ctx, loop, func(_ context.Context) (time.Duration, bool, error) {
		calls++
		if calls < 3 {
			return 0, false, errTransient
		}
		cancel()
		return 0, false, nil
	})

	sched.Next() // single tick; the inner retry loop handles the 2 failures + 1 success

	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("Run returned %v, want context.Canceled", err)
	}
	if bo.waited != 2 {
		t.Errorf("backoff.Wait called %d times, want 2", bo.waited)
	}
}

// TestCheckinLoop_401DoesNotRetry checks that 401 errors break the inner retry loop immediately.
func TestCheckinLoop_401DoesNotRetry(t *testing.T) {
	sched := newTracked()
	bo := &immediateBackoff{}
	loop := fleetgateway.New(sched, bo)
	ctx, cancel := context.WithCancel(context.Background())
	errUnauth := errors.New("invalid api key")

	calls := 0
	done := runLoop(ctx, loop, func(_ context.Context) (time.Duration, bool, error) {
		calls++
		if calls == 2 {
			cancel() // cancel inside execute to avoid racing with the ctx.Err() loop guard
		}
		return 0, true, errUnauth
	})

	sched.Next() // tick 1: execute called once, 401 returned, no backoff retry
	sched.Next() // tick 2: execute called once, cancel triggered, 401 returned

	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("Run returned %v, want context.Canceled", err)
	}
	if bo.waited != 0 {
		t.Errorf("backoff.Wait called %d times on 401, want 0", bo.waited)
	}
	if calls != 2 {
		t.Errorf("execute called %d times, want 2 (once per tick)", calls)
	}
}

// TestCheckinLoop_401EscalationAfterMaxCount checks that the scheduler interval is extended
// to ErrConsecutiveUnauthBackoff after 6 consecutive 401 failures.
func TestCheckinLoop_401EscalationAfterMaxCount(t *testing.T) {
	sched := newTracked()
	loop := fleetgateway.New(sched, &immediateBackoff{})
	ctx, cancel := context.WithCancel(context.Background())
	errUnauth := errors.New("invalid api key")

	calls := 0
	done := runLoop(ctx, loop, func(_ context.Context) (time.Duration, bool, error) {
		calls++
		if calls == 7 {
			cancel() // cancel inside execute to avoid racing with the ctx.Err() loop guard
		}
		return 0, true, errUnauth
	})

	// maxUnauthCounter is 6; the 7th tick pushes unauthCounter to 7 (> 6) and triggers escalation.
	for i := 0; i < 7; i++ {
		sched.Next()
	}
	<-done

	if len(sched.durations) == 0 {
		t.Fatal("SetDuration never called after 7 consecutive 401s")
	}
	last := sched.durations[len(sched.durations)-1]
	if last != fleetgateway.ErrConsecutiveUnauthBackoff {
		t.Errorf("SetDuration = %v, want ErrConsecutiveUnauthBackoff (%v)", last, fleetgateway.ErrConsecutiveUnauthBackoff)
	}
}

// TestCheckinLoop_NextIntervalApplied checks that a non-zero nextInterval from execute is
// forwarded to the scheduler.
func TestCheckinLoop_NextIntervalApplied(t *testing.T) {
	sched := newTracked()
	loop := fleetgateway.New(sched, &immediateBackoff{})
	ctx, cancel := context.WithCancel(context.Background())

	const want = 42 * time.Second
	done := runLoop(ctx, loop, func(_ context.Context) (time.Duration, bool, error) {
		cancel()
		return want, false, nil
	})

	sched.Next()
	<-done

	if len(sched.durations) == 0 {
		t.Fatal("SetDuration never called")
	}
	if sched.durations[0] != want {
		t.Errorf("SetDuration = %v, want %v", sched.durations[0], want)
	}
}

// TestCheckinLoop_CancelledContextExitsImmediately checks that Run returns context.Canceled
// without calling execute when the context is already cancelled.
func TestCheckinLoop_CancelledContextExitsImmediately(t *testing.T) {
	sched := newTracked()
	loop := fleetgateway.New(sched, &immediateBackoff{})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := loop.Run(ctx, func(_ context.Context) (time.Duration, bool, error) {
		t.Fatal("execute must not be called with a cancelled context")
		return 0, false, nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Errorf("Run returned %v, want context.Canceled", err)
	}
}
