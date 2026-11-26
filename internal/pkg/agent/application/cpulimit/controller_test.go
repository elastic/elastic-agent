// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package cpulimit

import (
	"context"
	"errors"
	"fmt"
	"math"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/pkg/core/logger/loggertest"
	"github.com/elastic/elastic-agent/pkg/limits"
)

const hostCPUs = 8

var (
	errBackend   = errors.New("backend failure")
	errNoSystemd = fmt.Errorf("probe: %w", &UnsupportedError{Reason: "no systemd"})
	quotaNone    = Quota{Kind: QuotaNone}
	capOff       = limits.CPULimit{}
)

func TestControllerAppliesCap(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newFakeBackend(hostCPUs)
		c, _ := start(t, f)

		c.Set(cpuLimit(t, 50))
		synctest.Wait()
		requireSnapshot(t, Snapshot{
			State: StateApplied, Configured: cpuLimit(t, 50), TargetCPUs: 4, ActiveQuota: quotaSet(4),
			EffectiveQuota: quotaSet(4),
		}, false, c.Snapshot())
		require.Equal(t, []string{"cpus", "inspect", "apply 4.00", "inspect"}, f.takeCalls())
		require.True(t, isClosed(c.Ready()))
		requireLastUpdate(t, c)
	})
}

func TestControllerBeforeFirstSet(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newFakeBackend(hostCPUs)
		c, stop := start(t, f)

		synctest.Wait()
		requireSnapshot(t, Snapshot{State: StateDisabled, Configured: capOff}, false, c.Snapshot())
		require.False(t, isClosed(c.Ready()))
		stop()
		require.Empty(t, f.takeCalls())
	})
}

func TestControllerSkipsWriteWhenQuotaIsInPlace(t *testing.T) {
	cases := []struct {
		name      string
		cpus      int
		percent   int
		quota     float64
		wantCalls []string
		wantQuota float64
	}{
		{name: "exact", cpus: 8, percent: 50, quota: 4, wantCalls: []string{"cpus", "inspect"}, wantQuota: 4},
		{name: "within tolerance", cpus: 8, percent: 50, quota: 4.009, wantCalls: []string{"cpus", "inspect"}, wantQuota: 4.009},
		{
			name: "outside tolerance", cpus: 8, percent: 50, quota: 4.02,
			wantCalls: []string{"cpus", "inspect", "apply 4.00", "inspect"}, wantQuota: 4,
		},
		{name: "within tolerance of a large host", cpus: 1000, percent: 1, quota: 10.09, wantCalls: []string{"cpus", "inspect"}, wantQuota: 10.09},
		{
			name: "outside tolerance of a large host", cpus: 1000, percent: 1, quota: 10.11,
			wantCalls: []string{"cpus", "inspect", "apply 10.00", "inspect"}, wantQuota: 10,
		},
		{name: "at the tolerance boundary", cpus: 10, percent: 11, quota: 1.11, wantCalls: []string{"cpus", "inspect"}, wantQuota: 1.11},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := newFakeBackend(tc.cpus)
				f.setQuota(quotaSet(tc.quota), true)
				c, _ := start(t, f)

				c.Set(cpuLimit(t, tc.percent))
				synctest.Wait()
				require.Equal(t, tc.wantCalls, f.takeCalls())
				s := c.Snapshot()
				require.Equal(t, StateApplied, s.State)
				require.Equal(t, quotaSet(tc.wantQuota), s.ActiveQuota)
			})
		})
	}
}

func TestControllerLatestRequestWins(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newFakeBackend(hostCPUs)
		release := make(chan struct{})
		f.onApply = func(ctx context.Context, cpus float64) error {
			if cpus == 4 {
				if err := wait(ctx, release); err != nil {
					return err
				}
			}
			f.setQuota(quotaSet(cpus), true)
			return nil
		}
		c, _ := start(t, f)

		c.Set(cpuLimit(t, 50))
		synctest.Wait()
		c.Set(cpuLimit(t, 25))
		c.Set(cpuLimit(t, 75))
		synctest.Wait()
		require.Equal(t, StatePending, c.Snapshot().State)

		close(release)
		synctest.Wait()
		require.Equal(t, []string{"cpus", "inspect", "apply 4.00", "cpus", "inspect", "apply 6.00", "inspect"}, f.takeCalls())
		requireSnapshot(t, Snapshot{
			State: StateApplied, Configured: cpuLimit(t, 75), TargetCPUs: 6, ActiveQuota: quotaSet(6),
			EffectiveQuota: quotaSet(6),
		}, false, c.Snapshot())
		requireLastUpdate(t, c)
	})
}

func TestControllerStalePassDoesNotPublish(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newFakeBackend(hostCPUs)
		releaseVerify := make(chan struct{})
		releaseCount := make(chan struct{})
		passes := 0
		f.onLogicalCPUs = func(ctx context.Context) (int, error) {
			passes++
			if passes == 2 {
				if err := wait(ctx, releaseCount); err != nil {
					return 0, err
				}
			}
			return hostCPUs, nil
		}
		inspects := 0
		f.onInspect = func(ctx context.Context) (Inspection, error) {
			inspects++
			if inspects == 2 {
				if err := wait(ctx, releaseVerify); err != nil {
					return Inspection{}, err
				}
			}
			return f.model(), nil
		}
		c, _ := start(t, f)

		c.Set(cpuLimit(t, 50))
		synctest.Wait()
		c.Set(cpuLimit(t, 25))
		require.Equal(t, cpuLimit(t, 25), (<-c.Updates()).Configured)
		close(releaseVerify)
		synctest.Wait()
		// The pass for 50 verified its quota after the change to 25. The pass for 25 waits for the CPU count.
		require.Equal(t, []string{"cpus", "inspect", "apply 4.00", "inspect", "cpus"}, f.takeCalls())
		require.Empty(t, c.Updates(), "the stale pass must not publish")
		requireSnapshot(t, Snapshot{State: StatePending, Configured: cpuLimit(t, 25)}, false, c.Snapshot())

		close(releaseCount)
		synctest.Wait()
		requireSnapshot(t, Snapshot{
			State: StateApplied, Configured: cpuLimit(t, 25), TargetCPUs: 2, ActiveQuota: quotaSet(2),
			EffectiveQuota: quotaSet(2),
		}, false, c.Snapshot())
	})
}

func TestControllerTurnsOffWhileApplyRuns(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newFakeBackend(hostCPUs)
		release := make(chan struct{})
		f.onApply = func(ctx context.Context, cpus float64) error {
			if err := wait(ctx, release); err != nil {
				return err
			}
			f.setQuota(quotaSet(cpus), true)
			return nil
		}
		c, stop := start(t, f)

		c.Set(cpuLimit(t, 50))
		synctest.Wait()
		c.Set(capOff)
		requireSnapshot(t, Snapshot{State: StateDisabled}, false, c.Snapshot())
		close(release)
		synctest.Wait()
		// The stale pass does not verify. The next pass removes the quota that the Apply wrote.
		require.Equal(t, []string{"cpus", "inspect", "apply 4.00", "inspect", "remove"}, f.takeCalls())
		requireSnapshot(t, Snapshot{State: StateDisabled}, false, c.Snapshot())
		require.Equal(t, quotaNone, f.serviceQuota())
		requireLastUpdate(t, c)

		stop()
		require.Empty(t, f.takeCalls())
	})
}

func TestControllerStalePassStopsAfterCPUCount(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newFakeBackend(hostCPUs)
		release := make(chan struct{})
		first := true
		f.onLogicalCPUs = func(ctx context.Context) (int, error) {
			if first {
				first = false
				if err := wait(ctx, release); err != nil {
					return 0, err
				}
			}
			return hostCPUs, nil
		}
		c, _ := start(t, f)

		c.Set(cpuLimit(t, 50))
		synctest.Wait()
		c.Set(cpuLimit(t, 25))
		close(release)
		synctest.Wait()
		require.Equal(t, []string{"cpus", "cpus", "inspect", "apply 2.00", "inspect"}, f.takeCalls())
		require.Equal(t, StateApplied, c.Snapshot().State)
	})
}

func TestControllerRetryUsesLatestRequest(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newFakeBackend(hostCPUs)
		f.onApply = func(context.Context, float64) error { return errBackend }
		c, _ := start(t, f)

		c.Set(cpuLimit(t, 50))
		synctest.Wait()
		require.Equal(t, StateDegraded, c.Snapshot().State)
		f.takeCalls()

		c.Set(capOff)
		synctest.Wait()
		require.Equal(t, []string{"inspect"}, f.takeCalls(), "the failed Apply wrote no quota, so none is removed")
		time.Sleep(recheckInterval)
		synctest.Wait()
		require.Empty(t, f.takeCalls(), "the retry for the old cap stops")
		requireSnapshot(t, Snapshot{State: StateDisabled}, false, c.Snapshot())
	})
}

func TestControllerRetryBackoff(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newFakeBackend(hostCPUs)
		f.onApply = func(context.Context, float64) error { return errBackend }
		c, _ := start(t, f)

		c.Set(cpuLimit(t, 50))
		synctest.Wait()
		require.Equal(t, 1, countApplies(f.takeCalls()))

		for _, seconds := range []int{5, 10, 20, 40, 60, 60} {
			requireApplyAfter(t, f, time.Duration(seconds)*time.Second)
		}

		require.Equal(t, StateDegraded, c.Snapshot().State)
		require.ErrorIs(t, c.Snapshot().Err, errBackend)
		require.False(t, isClosed(c.Ready()))
		c.Set(capOff)
		require.True(t, isClosed(c.Ready()))
	})
}

func TestControllerRetriesUntilApplied(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newFakeBackend(hostCPUs)
		failures := 1
		f.onApply = func(_ context.Context, cpus float64) error {
			if failures > 0 {
				failures--
				return errBackend
			}
			f.setQuota(quotaSet(cpus), true)
			return nil
		}
		c, _ := start(t, f)

		c.Set(cpuLimit(t, 50))
		synctest.Wait()
		requireSnapshot(t, Snapshot{
			State: StateDegraded, Configured: cpuLimit(t, 50), TargetCPUs: 4, ActiveQuota: quotaNone,
			EffectiveQuota: quotaNone,
		}, true, c.Snapshot())
		require.ErrorIs(t, c.Snapshot().Err, errBackend)
		require.False(t, isClosed(c.Ready()))

		time.Sleep(retryMinDelay)
		synctest.Wait()
		requireSnapshot(t, Snapshot{
			State: StateApplied, Configured: cpuLimit(t, 50), TargetCPUs: 4, ActiveQuota: quotaSet(4),
			EffectiveQuota: quotaSet(4),
		}, false, c.Snapshot())
		require.True(t, isClosed(c.Ready()))
	})
}

func TestControllerInspectsAfterTimeout(t *testing.T) {
	cases := []struct {
		name      string
		worked    bool
		atOnce    bool
		wantState State
		wantQuota Quota
	}{
		{name: "write worked", worked: true, wantState: StateApplied, wantQuota: quotaSet(4)},
		{name: "write did not work", wantState: StateDegraded, wantQuota: quotaNone},
		{name: "deadline error at once, write worked", worked: true, atOnce: true, wantState: StateApplied, wantQuota: quotaSet(4)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := newFakeBackend(hostCPUs)
				f.onApply = func(ctx context.Context, cpus float64) error {
					if tc.worked {
						f.setQuota(quotaSet(cpus), true)
					}
					if tc.atOnce {
						return context.DeadlineExceeded
					}
					<-ctx.Done()
					return ctx.Err()
				}
				c, _ := start(t, f)

				c.Set(cpuLimit(t, 50))
				if !tc.atOnce {
					synctest.Wait()
					require.Equal(t, StatePending, c.Snapshot().State)
					time.Sleep(callTimeout)
				}
				synctest.Wait()
				require.Equal(t, []string{"cpus", "inspect", "apply 4.00", "inspect"}, f.takeCalls())
				requireSnapshot(t, Snapshot{
					State: tc.wantState, Configured: cpuLimit(t, 50), TargetCPUs: 4, ActiveQuota: tc.wantQuota,
					EffectiveQuota: tc.wantQuota,
				}, !tc.worked, c.Snapshot())
				require.Equal(t, tc.worked, isClosed(c.Ready()))
			})
		})
	}
}

func TestControllerReportsFailures(t *testing.T) {
	cases := []struct {
		name      string
		setup     func(f *fakeBackend)
		wantCalls []string
		want      Snapshot
		errIs     error
	}{
		{
			name:      "CPU count read fails",
			setup:     func(f *fakeBackend) { f.onLogicalCPUs = func(context.Context) (int, error) { return 0, errBackend } },
			wantCalls: []string{"cpus"},
			errIs:     errBackend,
		},
		{
			name:      "CPU count is zero",
			setup:     func(f *fakeBackend) { f.onLogicalCPUs = func(context.Context) (int, error) { return 0, nil } },
			wantCalls: []string{"cpus"},
		},
		{
			name: "inspect fails",
			setup: func(f *fakeBackend) {
				f.onInspect = func(context.Context) (Inspection, error) { return Inspection{}, errBackend }
			},
			wantCalls: []string{"cpus", "inspect"},
			want:      Snapshot{TargetCPUs: 4},
			errIs:     errBackend,
		},
		{
			name: "apply sets a wrong quota",
			setup: func(f *fakeBackend) {
				f.onApply = func(context.Context, float64) error {
					f.setQuota(quotaSet(3), true)
					return nil
				}
			},
			wantCalls: []string{"cpus", "inspect", "apply 4.00", "inspect"},
			want:      Snapshot{TargetCPUs: 4, ActiveQuota: quotaSet(3), EffectiveQuota: quotaSet(3)},
		},
		{
			name: "apply fails although it wrote the quota",
			setup: func(f *fakeBackend) {
				f.onApply = func(_ context.Context, cpus float64) error {
					f.setQuota(quotaSet(cpus), true)
					return errBackend
				}
			},
			wantCalls: []string{"cpus", "inspect", "apply 4.00", "inspect"},
			want:      Snapshot{TargetCPUs: 4, ActiveQuota: quotaSet(4), EffectiveQuota: quotaSet(4)},
			errIs:     errBackend,
		},
		{
			name: "inspect returns NaN",
			setup: func(f *fakeBackend) {
				f.onInspect = func(context.Context) (Inspection, error) {
					return Inspection{Service: quotaSet(math.NaN()), Effective: quotaSet(4)}, nil
				}
			},
			wantCalls: []string{"cpus", "inspect"},
			want:      Snapshot{TargetCPUs: 4},
		},
		{
			name: "inspect returns Inf",
			setup: func(f *fakeBackend) {
				f.onInspect = func(context.Context) (Inspection, error) {
					return Inspection{Service: quotaSet(math.Inf(1)), Effective: quotaSet(4)}, nil
				}
			},
			wantCalls: []string{"cpus", "inspect"},
			want:      Snapshot{TargetCPUs: 4},
		},
		{
			name: "apply leaves the quota unconfirmed",
			setup: func(f *fakeBackend) {
				f.setQuota(quotaSet(4), true)
				f.setUnconfirmed()
				f.onApply = func(context.Context, float64) error { return nil }
			},
			wantCalls: []string{"cpus", "inspect", "apply 4.00", "inspect"},
			want:      Snapshot{TargetCPUs: 4, EffectiveQuota: quotaSet(4)},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := newFakeBackend(hostCPUs)
				tc.setup(f)
				c, _ := start(t, f)

				c.Set(cpuLimit(t, 50))
				synctest.Wait()
				require.Equal(t, tc.wantCalls, f.takeCalls())
				want := tc.want
				want.State = StateDegraded
				want.Configured = cpuLimit(t, 50)
				requireSnapshot(t, want, true, c.Snapshot())
				if tc.errIs != nil {
					require.ErrorIs(t, c.Snapshot().Err, tc.errIs)
				}
				require.False(t, isClosed(c.Ready()))
			})
		})
	}
}

func TestControllerChangePendingKeepsMeasuredQuota(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newFakeBackend(hostCPUs)
		release := make(chan struct{})
		f.onApply = func(ctx context.Context, cpus float64) error {
			if cpus == 2 {
				if err := wait(ctx, release); err != nil {
					return err
				}
			}
			f.setQuota(quotaSet(cpus), true)
			return nil
		}
		c, _ := start(t, f)

		c.Set(cpuLimit(t, 50))
		synctest.Wait()

		c.Set(cpuLimit(t, 25))
		synctest.Wait()
		requireSnapshot(t, Snapshot{
			State:          StatePending,
			Configured:     cpuLimit(t, 25),
			TargetCPUs:     2,
			ActiveQuota:    quotaSet(4),
			EffectiveQuota: quotaSet(4),
		}, false, c.Snapshot())

		close(release)
		synctest.Wait()
		requireSnapshot(t, Snapshot{
			State: StateApplied, Configured: cpuLimit(t, 25), TargetCPUs: 2, ActiveQuota: quotaSet(2),
			EffectiveQuota: quotaSet(2),
		}, false, c.Snapshot())
	})
}

func TestControllerRecheckFixesDrift(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newFakeBackend(hostCPUs)
		release := make(chan struct{})
		applies := 0
		f.onApply = func(ctx context.Context, cpus float64) error {
			applies++
			if applies == 2 {
				if err := wait(ctx, release); err != nil {
					return err
				}
			}
			f.setQuota(quotaSet(cpus), true)
			return nil
		}
		c, _ := start(t, f)

		c.Set(cpuLimit(t, 50))
		synctest.Wait()
		before := c.Snapshot()
		f.takeCalls()
		f.setQuota(quotaSet(6), false)

		c.Set(cpuLimit(t, 50))
		synctest.Wait()
		want := before
		want.State = StatePending
		require.Equal(t, want, c.Snapshot(), "a correction is pending and keeps the last measured quota")

		close(release)
		synctest.Wait()
		require.Equal(t, []string{"cpus", "inspect", "apply 4.00", "inspect"}, f.takeCalls())
		requireSnapshot(t, Snapshot{
			State: StateApplied, Configured: cpuLimit(t, 50), TargetCPUs: 4, ActiveQuota: quotaSet(4),
			EffectiveQuota: quotaSet(4),
		}, false, c.Snapshot())
	})
}

func TestControllerCapOffRemovesOwnQuota(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newFakeBackend(hostCPUs)
		release := make(chan struct{})
		f.onRemove = func(ctx context.Context) error {
			if err := wait(ctx, release); err != nil {
				return err
			}
			f.setQuota(quotaNone, false)
			return nil
		}
		c, stop := start(t, f)

		c.Set(cpuLimit(t, 50))
		synctest.Wait()
		f.takeCalls()

		c.Set(capOff)
		synctest.Wait()
		requireSnapshot(t, Snapshot{
			State: StatePending, ActiveQuota: quotaSet(4), EffectiveQuota: quotaSet(4),
		}, false, c.Snapshot())
		close(release)
		synctest.Wait()
		require.Equal(t, []string{"inspect", "remove"}, f.takeCalls())
		requireSnapshot(t, Snapshot{State: StateDisabled}, false, c.Snapshot())
		require.Equal(t, quotaNone, f.serviceQuota())
		requireLastUpdate(t, c)

		time.Sleep(10 * recheckInterval)
		synctest.Wait()
		require.Empty(t, f.takeCalls(), "no recheck with the cap off")
		require.Empty(t, c.Updates())

		stop()
		require.Empty(t, f.takeCalls(), "the removed quota is not removed again")
	})
}

func TestControllerCapOffChecksQuotaBeforeRemoval(t *testing.T) {
	cases := []struct {
		name string
		// prepare sets up f before Run starts and returns the steps to run before the cap goes off.
		prepare   func(t *testing.T, f *fakeBackend) func(c *Controller)
		wantCalls []string
		wantQuota Quota
	}{
		{
			name: "a quota equal to the verified one",
			prepare: func(t *testing.T, f *fakeBackend) func(c *Controller) {
				f.cpus = 2
				return func(c *Controller) {
					c.Set(cpuLimit(t, 50))
					synctest.Wait()
					f.setQuota(quotaSet(1), true)
				}
			},
			wantCalls: []string{"inspect", "remove"},
			wantQuota: quotaNone,
		},
		{
			name: "a quota close to the verified one",
			prepare: func(t *testing.T, f *fakeBackend) func(c *Controller) {
				f.cpus = 2
				return func(c *Controller) {
					c.Set(cpuLimit(t, 50))
					synctest.Wait()
					f.setQuota(quotaSet(1.01), true)
				}
			},
			wantCalls: []string{"inspect"},
			wantQuota: quotaSet(1.01),
		},
		{
			name: "a quota changed by someone else",
			prepare: func(t *testing.T, f *fakeBackend) func(c *Controller) {
				return func(c *Controller) {
					c.Set(cpuLimit(t, 50))
					synctest.Wait()
					f.setQuota(quotaSet(2), true)
				}
			},
			wantCalls: []string{"inspect"},
			wantQuota: quotaSet(2),
		},
		{
			name: "a quota removed by someone else",
			prepare: func(t *testing.T, f *fakeBackend) func(c *Controller) {
				return func(c *Controller) {
					c.Set(cpuLimit(t, 50))
					synctest.Wait()
					f.setQuota(quotaNone, false)
				}
			},
			wantCalls: []string{"inspect"},
			wantQuota: quotaNone,
		},
		{
			name: "a quota of the verified value that the agent does not hold",
			prepare: func(t *testing.T, f *fakeBackend) func(c *Controller) {
				return func(c *Controller) {
					c.Set(cpuLimit(t, 50))
					synctest.Wait()
					f.setQuota(quotaSet(4), false)
				}
			},
			// The controller cannot tell this quota from its own. Remove keeps it.
			wantCalls: []string{"inspect", "remove"},
			wantQuota: quotaSet(4),
		},
		{
			name: "an unconfirmed quota after a verified one",
			prepare: func(t *testing.T, f *fakeBackend) func(c *Controller) {
				return func(c *Controller) {
					c.Set(cpuLimit(t, 50))
					synctest.Wait()
					f.setUnconfirmed()
				}
			},
			wantCalls: []string{"inspect", "remove"},
			wantQuota: quotaNone,
		},
		{
			name: "a failed apply that wrote the quota",
			prepare: func(t *testing.T, f *fakeBackend) func(c *Controller) {
				f.onApply = func(ctx context.Context, cpus float64) error {
					f.setQuota(quotaSet(cpus), true)
					return errBackend
				}
				return func(c *Controller) { c.Set(cpuLimit(t, 50)) }
			},
			wantCalls: []string{"inspect", "remove"},
			wantQuota: quotaNone,
		},
		{
			name: "a quota changed by someone else after a failed apply that wrote the quota",
			prepare: func(t *testing.T, f *fakeBackend) func(c *Controller) {
				f.onApply = func(ctx context.Context, cpus float64) error {
					f.setQuota(quotaSet(cpus), true)
					return errBackend
				}
				return func(c *Controller) {
					c.Set(cpuLimit(t, 50))
					synctest.Wait()
					f.setQuota(quotaSet(2), true)
				}
			},
			wantCalls: []string{"inspect"},
			wantQuota: quotaSet(2),
		},
		{
			name: "a quota set by someone else after an apply that was not verified",
			prepare: func(t *testing.T, f *fakeBackend) func(c *Controller) {
				f.onApply = func(context.Context, float64) error { return errBackend }
				return func(c *Controller) {
					c.Set(cpuLimit(t, 50))
					synctest.Wait()
					f.setQuota(quotaSet(2), false)
				}
			},
			// With no verified quota, the controller cannot tell whether the Apply wrote this quota. Remove keeps it.
			wantCalls: []string{"inspect", "remove"},
			wantQuota: quotaSet(2),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := newFakeBackend(hostCPUs)
				steps := tc.prepare(t, f)
				c, stop := start(t, f)

				steps(c)
				synctest.Wait()
				f.takeCalls()
				c.Set(capOff)
				synctest.Wait()
				require.Equal(t, tc.wantCalls, f.takeCalls())
				requireSnapshot(t, Snapshot{State: StateDisabled}, false, c.Snapshot())

				stop()
				require.Empty(t, f.takeCalls(), "the quota is no longer owned, so the exit leaves it alone")
				require.Equal(t, tc.wantQuota, f.serviceQuota())
			})
		})
	}
}

func TestControllerCapOffRemovalRetries(t *testing.T) {
	cases := []struct {
		name      string
		setup     func(f *fakeBackend, failing *atomic.Bool)
		wantCalls []string
		wantQuota Quota
	}{
		{
			name: "inspect fails",
			setup: func(f *fakeBackend, failing *atomic.Bool) {
				f.onInspect = func(context.Context) (Inspection, error) {
					if failing.Load() {
						return Inspection{}, errBackend
					}
					return f.model(), nil
				}
			},
			wantCalls: []string{"inspect"},
		},
		{
			name: "remove fails",
			setup: func(f *fakeBackend, failing *atomic.Bool) {
				f.onRemove = func(context.Context) error {
					if failing.Load() {
						return errBackend
					}
					f.setQuota(quotaNone, false)
					return nil
				}
			},
			wantCalls: []string{"inspect", "remove"},
			wantQuota: quotaSet(4),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := newFakeBackend(hostCPUs)
				var failing atomic.Bool
				tc.setup(f, &failing)
				c, stop := start(t, f)

				c.Set(cpuLimit(t, 50))
				synctest.Wait()
				f.takeCalls()
				failing.Store(true)
				c.Set(capOff)
				synctest.Wait()
				require.Equal(t, tc.wantCalls, f.takeCalls())
				requireSnapshot(t, Snapshot{
					State: StateDegraded, ActiveQuota: tc.wantQuota, EffectiveQuota: tc.wantQuota,
				}, true, c.Snapshot())
				require.ErrorIs(t, c.Snapshot().Err, errBackend)

				for _, seconds := range []int{5, 10, 20, 40, 60, 60} {
					requireCallsAfter(t, f, time.Duration(seconds)*time.Second, tc.wantCalls)
				}
				failing.Store(false)
				requireCallsAfter(t, f, retryMaxDelay, []string{"inspect", "remove"})
				requireSnapshot(t, Snapshot{State: StateDisabled}, false, c.Snapshot())
				require.Equal(t, quotaNone, f.serviceQuota())

				time.Sleep(10 * recheckInterval)
				synctest.Wait()
				stop()
				require.Empty(t, f.takeCalls())
			})
		})
	}
}

func TestControllerCapOnDuringRemoval(t *testing.T) {
	t.Run("after a failed removal", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			f := newFakeBackend(hostCPUs)
			f.onRemove = func(context.Context) error { return errBackend }
			c, _ := start(t, f)

			c.Set(cpuLimit(t, 50))
			synctest.Wait()
			c.Set(capOff)
			synctest.Wait()
			require.Equal(t, StateDegraded, c.Snapshot().State)
			f.takeCalls()

			c.Set(cpuLimit(t, 50))
			synctest.Wait()
			require.Equal(t, []string{"cpus", "inspect"}, f.takeCalls())
			requireSnapshot(t, Snapshot{
				State: StateApplied, Configured: cpuLimit(t, 50), TargetCPUs: 4, ActiveQuota: quotaSet(4),
				EffectiveQuota: quotaSet(4),
			}, false, c.Snapshot())
			time.Sleep(10 * recheckInterval)
			synctest.Wait()
			require.NotContains(t, f.takeCalls(), "remove")
		})
	})
	t.Run("while the removal checks the quota", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			f := newFakeBackend(hostCPUs)
			release := make(chan struct{})
			inspects := 0
			f.onInspect = func(ctx context.Context) (Inspection, error) {
				inspects++
				if inspects == 3 {
					if err := wait(ctx, release); err != nil {
						return Inspection{}, err
					}
				}
				return f.model(), nil
			}
			c, _ := start(t, f)

			c.Set(cpuLimit(t, 50))
			synctest.Wait()
			f.takeCalls()
			c.Set(capOff)
			synctest.Wait()
			c.Set(cpuLimit(t, 50))
			close(release)
			synctest.Wait()
			require.Equal(t, []string{"inspect", "cpus", "inspect"}, f.takeCalls(), "the stale removal does not remove")
			require.Equal(t, StateApplied, c.Snapshot().State)
			require.Equal(t, quotaSet(4), f.serviceQuota())
		})
	})
	t.Run("while the removal removes the quota", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			f := newFakeBackend(hostCPUs)
			release := make(chan struct{})
			f.onRemove = func(ctx context.Context) error {
				if err := wait(ctx, release); err != nil {
					return err
				}
				f.setQuota(quotaNone, false)
				return nil
			}
			c, _ := start(t, f)

			c.Set(cpuLimit(t, 50))
			synctest.Wait()
			f.takeCalls()
			c.Set(capOff)
			synctest.Wait()
			c.Set(cpuLimit(t, 25))
			close(release)
			synctest.Wait()
			require.Equal(t, []string{"inspect", "remove", "cpus", "inspect", "apply 2.00", "inspect"}, f.takeCalls())
			requireSnapshot(t, Snapshot{
				State: StateApplied, Configured: cpuLimit(t, 25), TargetCPUs: 2, ActiveQuota: quotaSet(2),
				EffectiveQuota: quotaSet(2),
			}, false, c.Snapshot())
			requireLastUpdate(t, c)
			require.Equal(t, quotaSet(2), f.serviceQuota())
		})
	})
}

// TestControllerStaleRemovalSettlesState checks the state when a stale removal pass ends the ownership. The pass for
// the newest cap-off request has nothing to remove, but it must still show the cap as off.
func TestControllerStaleRemovalSettlesState(t *testing.T) {
	cases := []struct {
		name string
		// setup makes the removal block until release is closed.
		setup     func(f *fakeBackend, release <-chan struct{})
		wantCalls []string
		wantQuota Quota
	}{
		{
			name: "the removal succeeds",
			setup: func(f *fakeBackend, release <-chan struct{}) {
				f.onRemove = func(ctx context.Context) error {
					if err := wait(ctx, release); err != nil {
						return err
					}
					f.setQuota(quotaNone, false)
					return nil
				}
			},
			wantCalls: []string{"inspect", "remove"},
			wantQuota: quotaNone,
		},
		{
			name: "the quota was changed by someone else",
			setup: func(f *fakeBackend, release <-chan struct{}) {
				blockRemovalInspect(f, release, func() (Inspection, error) {
					f.setQuota(quotaSet(2), false)
					return f.model(), nil
				})
			},
			wantCalls: []string{"inspect"},
			wantQuota: quotaSet(2),
		},
		{
			name: "unsupported",
			setup: func(f *fakeBackend, release <-chan struct{}) {
				blockRemovalInspect(f, release, func() (Inspection, error) { return Inspection{}, errNoSystemd })
			},
			wantCalls: []string{"inspect"},
			wantQuota: quotaSet(4),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := newFakeBackend(hostCPUs)
				release := make(chan struct{})
				tc.setup(f, release)
				c, stop := start(t, f)

				c.Set(cpuLimit(t, 50))
				synctest.Wait()
				f.takeCalls()
				c.Set(capOff)
				synctest.Wait()
				c.Set(cpuLimit(t, 50))
				c.Set(capOff)
				close(release)
				synctest.Wait()
				require.Equal(t, tc.wantCalls, f.takeCalls())
				requireSnapshot(t, Snapshot{State: StateDisabled}, false, c.Snapshot())
				requireLastUpdate(t, c)

				time.Sleep(10 * recheckInterval)
				synctest.Wait()
				stop()
				require.Empty(t, f.takeCalls())
				require.Equal(t, tc.wantQuota, f.serviceQuota())
			})
		})
	}
}

// blockRemovalInspect makes the third Inspect, the first one after the cap goes off, wait for release and then return
// the result of removal. The other calls use the model.
func blockRemovalInspect(f *fakeBackend, release <-chan struct{}, removal func() (Inspection, error)) {
	inspects := 0
	f.onInspect = func(ctx context.Context) (Inspection, error) {
		inspects++
		if inspects != 3 {
			return f.model(), nil
		}
		if err := wait(ctx, release); err != nil {
			return Inspection{}, err
		}
		return removal()
	}
}

func TestControllerCapOffRemovalUnsupported(t *testing.T) {
	cases := []struct {
		name      string
		setup     func(f *fakeBackend, unsupported *atomic.Bool)
		wantCalls []string
	}{
		{
			name: "inspect unsupported",
			setup: func(f *fakeBackend, unsupported *atomic.Bool) {
				f.onInspect = func(context.Context) (Inspection, error) {
					if unsupported.Load() {
						return Inspection{}, errNoSystemd
					}
					return f.model(), nil
				}
			},
			wantCalls: []string{"inspect"},
		},
		{
			name: "remove unsupported",
			setup: func(f *fakeBackend, unsupported *atomic.Bool) {
				f.onRemove = func(context.Context) error { return errNoSystemd }
			},
			wantCalls: []string{"inspect", "remove"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := newFakeBackend(hostCPUs)
				var unsupported atomic.Bool
				tc.setup(f, &unsupported)
				c, stop := start(t, f)

				c.Set(cpuLimit(t, 50))
				synctest.Wait()
				f.takeCalls()
				unsupported.Store(true)
				c.Set(capOff)
				synctest.Wait()
				require.Equal(t, tc.wantCalls, f.takeCalls())
				requireSnapshot(t, Snapshot{State: StateDisabled}, false, c.Snapshot())

				time.Sleep(10 * recheckInterval)
				synctest.Wait()
				stop()
				require.Empty(t, f.takeCalls(), "unsupported is not retried")
			})
		})
	}
}

func TestControllerCapOffAtStart(t *testing.T) {
	cases := []struct {
		name      string
		quota     Quota
		agentHeld bool
	}{
		{name: "no quota", quota: quotaNone},
		{name: "quota set by someone else", quota: quotaSet(2)},
		{name: "agent leftover", quota: quotaSet(2), agentHeld: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := newFakeBackend(hostCPUs)
				f.setQuota(tc.quota, tc.agentHeld)
				c, stop := start(t, f)

				c.Set(capOff)
				require.True(t, isClosed(c.Ready()))
				time.Sleep(10 * recheckInterval)
				synctest.Wait()
				requireSnapshot(t, Snapshot{State: StateDisabled}, false, c.Snapshot())

				stop()
				require.Empty(t, f.takeCalls())
				require.Equal(t, tc.quota, f.serviceQuota())
			})
		})
	}
}

func TestControllerCapOffHidesQuotasAtOnce(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newFakeBackend(hostCPUs)
		f.setQuota(quotaSet(2), false)
		f.onApply = func(context.Context, float64) error { return errNoSystemd }
		c, _ := start(t, f)

		c.Set(cpuLimit(t, 50))
		synctest.Wait()
		s := c.Snapshot()
		require.Equal(t, StateUnsupported, s.State)
		require.Equal(t, quotaSet(2), s.ActiveQuota)
		require.Equal(t, quotaSet(2), s.EffectiveQuota)

		c.Set(capOff)
		requireSnapshot(t, Snapshot{State: StateDisabled}, false, c.Snapshot())
	})
}

func TestControllerCapOffMakesNoBackendCalls(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newFakeBackend(hostCPUs)
		c, stop := start(t, f)

		c.Set(capOff)
		require.True(t, isClosed(c.Ready()))
		requireLastUpdate(t, c)
		for range 4 {
			c.Set(capOff)
			synctest.Wait()
			time.Sleep(recheckInterval)
		}
		synctest.Wait()
		requireSnapshot(t, Snapshot{State: StateDisabled}, false, c.Snapshot())
		stop()
		require.Empty(t, f.takeCalls())
	})
}

func TestControllerUnsupported(t *testing.T) {
	cases := []struct {
		name      string
		setup     func(f *fakeBackend)
		wantCalls []string
		want      Snapshot
	}{
		{
			name:      "CPU count unsupported",
			setup:     func(f *fakeBackend) { f.onLogicalCPUs = func(context.Context) (int, error) { return 0, errNoSystemd } },
			wantCalls: []string{"cpus"},
			want:      Snapshot{State: StateUnsupported, Reason: "no systemd"},
		},
		{
			name: "inspect unsupported",
			setup: func(f *fakeBackend) {
				f.onInspect = func(context.Context) (Inspection, error) { return Inspection{}, errNoSystemd }
			},
			wantCalls: []string{"cpus", "inspect"},
			want:      Snapshot{State: StateUnsupported, TargetCPUs: 4, Reason: "no systemd"},
		},
		{
			name:      "apply unsupported",
			setup:     func(f *fakeBackend) { f.onApply = func(context.Context, float64) error { return errNoSystemd } },
			wantCalls: []string{"cpus", "inspect", "apply 4.00", "inspect"},
			want: Snapshot{
				State: StateUnsupported, TargetCPUs: 4, ActiveQuota: quotaNone, EffectiveQuota: quotaNone, Reason: "no systemd",
			},
		},
		{
			name: "verification unsupported",
			setup: func(f *fakeBackend) {
				inspects := 0
				f.onInspect = func(context.Context) (Inspection, error) {
					inspects++
					if inspects == 2 {
						return Inspection{}, errNoSystemd
					}
					return f.model(), nil
				}
			},
			wantCalls: []string{"cpus", "inspect", "apply 4.00", "inspect"},
			want:      Snapshot{State: StateUnsupported, TargetCPUs: 4, Reason: "no systemd"},
		},
		{
			name: "apply and verification unsupported",
			setup: func(f *fakeBackend) {
				inspects := 0
				f.onInspect = func(context.Context) (Inspection, error) {
					inspects++
					if inspects == 2 {
						return Inspection{}, errNoSystemd
					}
					return f.model(), nil
				}
				f.onApply = func(context.Context, float64) error { return errNoSystemd }
			},
			wantCalls: []string{"cpus", "inspect", "apply 4.00", "inspect"},
			want:      Snapshot{State: StateUnsupported, TargetCPUs: 4, Reason: "no systemd"},
		},
		{
			name: "apply times out and verification unsupported",
			setup: func(f *fakeBackend) {
				inspects := 0
				f.onInspect = func(context.Context) (Inspection, error) {
					inspects++
					if inspects == 2 {
						return Inspection{}, errNoSystemd
					}
					return f.model(), nil
				}
				f.onApply = func(context.Context, float64) error { return context.DeadlineExceeded }
			},
			wantCalls: []string{"cpus", "inspect", "apply 4.00", "inspect"},
			want:      Snapshot{State: StateUnsupported, TargetCPUs: 4, Reason: "no systemd"},
		},
		{
			name: "apply fails and verification unsupported",
			setup: func(f *fakeBackend) {
				inspects := 0
				f.onInspect = func(context.Context) (Inspection, error) {
					inspects++
					if inspects == 2 {
						return Inspection{}, errNoSystemd
					}
					return f.model(), nil
				}
				f.onApply = func(context.Context, float64) error { return errBackend }
			},
			wantCalls: []string{"cpus", "inspect", "apply 4.00", "inspect"},
			want:      Snapshot{State: StateUnsupported, TargetCPUs: 4, Reason: "no systemd"},
		},
		{
			name: "apply unsupported and verification fails",
			setup: func(f *fakeBackend) {
				inspects := 0
				f.onInspect = func(context.Context) (Inspection, error) {
					inspects++
					if inspects == 2 {
						return Inspection{}, errBackend
					}
					return f.model(), nil
				}
				f.onApply = func(context.Context, float64) error { return errNoSystemd }
			},
			wantCalls: []string{"cpus", "inspect", "apply 4.00", "inspect"},
			want:      Snapshot{State: StateUnsupported, TargetCPUs: 4, Reason: "no systemd"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := newFakeBackend(hostCPUs)
				tc.setup(f)
				c, _ := start(t, f)

				c.Set(cpuLimit(t, 50))
				synctest.Wait()
				require.Equal(t, tc.wantCalls, f.takeCalls())
				want := tc.want
				want.Configured = cpuLimit(t, 50)
				requireSnapshot(t, want, false, c.Snapshot())
				require.True(t, isClosed(c.Ready()))

				time.Sleep(recheckInterval)
				synctest.Wait()
				require.Empty(t, f.takeCalls(), "unsupported is not retried or rechecked")
			})
		})
	}
}

func TestControllerShutdownDuringHangingCall(t *testing.T) {
	hang := func(ctx context.Context) error {
		<-ctx.Done()
		return ctx.Err()
	}
	cases := []struct {
		name      string
		setup     func(f *fakeBackend)
		wantCalls []string
		want      Snapshot
	}{
		{
			name:      "CPU count",
			setup:     func(f *fakeBackend) { f.onLogicalCPUs = func(ctx context.Context) (int, error) { return 0, hang(ctx) } },
			wantCalls: []string{"cpus"},
			want:      Snapshot{State: StatePending},
		},
		{
			name: "inspect",
			setup: func(f *fakeBackend) {
				f.onInspect = func(ctx context.Context) (Inspection, error) { return Inspection{}, hang(ctx) }
			},
			wantCalls: []string{"cpus", "inspect"},
			want:      Snapshot{State: StatePending},
		},
		{
			name:  "apply",
			setup: func(f *fakeBackend) { f.onApply = func(ctx context.Context, _ float64) error { return hang(ctx) } },
			// The apply may have written the quota, so Run checks the quota when it stops.
			wantCalls: []string{"cpus", "inspect", "apply 4.00", "inspect"},
			want:      Snapshot{State: StatePending},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := newFakeBackend(hostCPUs)
				tc.setup(f)
				c, stop := start(t, f)

				c.Set(cpuLimit(t, 50))
				synctest.Wait()
				require.Equal(t, StatePending, c.Snapshot().State)
				stop()

				want := tc.want
				want.Configured = cpuLimit(t, 50)
				requireSnapshot(t, want, false, c.Snapshot())
				requireLastUpdate(t, c)

				// Set still returns after Run ended, and the newest Snapshot replaces an unread one.
				c.Set(cpuLimit(t, 25))
				c.Set(cpuLimit(t, 75))
				synctest.Wait()
				s := <-c.Updates()
				require.Equal(t, StatePending, s.State)
				require.Equal(t, cpuLimit(t, 75), s.Configured)
				require.Empty(t, c.Updates())
				require.Equal(t, tc.wantCalls, f.takeCalls())
			})
		})
	}
}

func TestControllerSameValueSetDoesNotStarve(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newFakeBackend(hostCPUs)
		f.onInspect = func(ctx context.Context) (Inspection, error) {
			select {
			case <-time.After(200 * time.Millisecond):
			case <-ctx.Done():
				return Inspection{}, ctx.Err()
			}
			return f.model(), nil
		}
		c, _ := start(t, f)

		for range 20 {
			c.Set(cpuLimit(t, 50))
			time.Sleep(100 * time.Millisecond)
		}
		synctest.Wait()
		s := c.Snapshot()
		require.Equal(t, StateApplied, s.State)
		require.Equal(t, quotaSet(4), s.ActiveQuota)
		require.True(t, isClosed(c.Ready()))
		requireLastUpdate(t, c)
	})
}

func TestControllerChangeClearsOldFailure(t *testing.T) {
	cases := []struct {
		name        string
		next        int
		wantPending Snapshot
		wantDone    Snapshot
	}{
		{
			name:        "another cap",
			next:        25,
			wantPending: Snapshot{State: StatePending, TargetCPUs: 2, ActiveQuota: quotaNone, EffectiveQuota: quotaNone},
			wantDone:    Snapshot{State: StateApplied, TargetCPUs: 2, ActiveQuota: quotaSet(2), EffectiveQuota: quotaSet(2)},
		},
		{
			name:        "cap off",
			wantPending: Snapshot{State: StatePending, ActiveQuota: quotaNone, EffectiveQuota: quotaNone},
			wantDone:    Snapshot{State: StateDisabled},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := newFakeBackend(hostCPUs)
				f.onApply = func(_ context.Context, cpus float64) error {
					if cpus == 4 {
						return errBackend
					}
					f.setQuota(quotaSet(cpus), true)
					return nil
				}
				release := make(chan struct{})
				inspects := 0
				f.onInspect = func(ctx context.Context) (Inspection, error) {
					inspects++
					if inspects == 3 {
						if err := wait(ctx, release); err != nil {
							return Inspection{}, err
						}
					}
					return f.model(), nil
				}
				c, _ := start(t, f)

				c.Set(cpuLimit(t, 50))
				synctest.Wait()
				require.Equal(t, StateDegraded, c.Snapshot().State)
				next := capOff
				if tc.next > 0 {
					next = cpuLimit(t, tc.next)
				}
				c.Set(next)
				synctest.Wait()
				want := tc.wantPending
				want.Configured = next
				requireSnapshot(t, want, false, c.Snapshot())

				close(release)
				synctest.Wait()
				want = tc.wantDone
				want.Configured = next
				requireSnapshot(t, want, false, c.Snapshot())
			})
		})
	}
}

func TestControllerUnconfirmedQuota(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newFakeBackend(hostCPUs)
		f.setQuota(quotaSet(4), true)
		f.setUnconfirmed()
		c, _ := start(t, f)

		c.Set(cpuLimit(t, 50))
		synctest.Wait()
		require.Equal(t, []string{"cpus", "inspect", "apply 4.00", "inspect"}, f.takeCalls())
		requireSnapshot(t, Snapshot{
			State: StateApplied, Configured: cpuLimit(t, 50), TargetCPUs: 4, ActiveQuota: quotaSet(4),
			EffectiveQuota: quotaSet(4),
		}, false, c.Snapshot())
	})
}

func TestControllerTurnsCapOnAfterOff(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newFakeBackend(hostCPUs)
		f.setQuota(quotaSet(2), true)
		c, _ := start(t, f)

		c.Set(capOff)
		synctest.Wait()
		require.Empty(t, f.takeCalls())

		c.Set(cpuLimit(t, 50))
		require.Equal(t, StatePending, c.Snapshot().State)
		synctest.Wait()
		require.Equal(t, []string{"cpus", "inspect", "apply 4.00", "inspect"}, f.takeCalls())
		requireSnapshot(t, Snapshot{
			State: StateApplied, Configured: cpuLimit(t, 50), TargetCPUs: 4, ActiveQuota: quotaSet(4),
			EffectiveQuota: quotaSet(4),
		}, false, c.Snapshot())

		time.Sleep(recheckInterval)
		synctest.Wait()
		require.Equal(t, []string{"cpus", "inspect"}, f.takeCalls(), "the recheck runs again")
	})
}

func TestControllerUpdatesWithConcurrentReader(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newFakeBackend(hostCPUs)
		c, _ := start(t, f)

		var mu sync.Mutex
		var last Snapshot
		done := make(chan struct{})
		go func() {
			for {
				select {
				case s := <-c.Updates():
					mu.Lock()
					last = s
					mu.Unlock()
				case <-done:
					return
				}
			}
		}()

		for i := range 200 {
			c.Set(cpuLimit(t, 1+i%100))
			if i%10 == 0 {
				c.Set(capOff)
			}
		}
		synctest.Wait()
		mu.Lock()
		require.Equal(t, c.Snapshot(), last)
		mu.Unlock()
		close(done)
	})
}

func TestControllerRunDoesNotStartPassAfterCancel(t *testing.T) {
	// When the wake and the cancelled ctx are both ready, select picks one at random, so the test repeats.
	for range 20 {
		f := newFakeBackend(hostCPUs)
		log, _ := loggertest.New(t.Name())
		c := NewController(log, f)
		c.Set(cpuLimit(t, 50))
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		require.NoError(t, c.Run(ctx))
		require.Empty(t, f.takeCalls())
	}
}

func TestControllerExitRemovesOwnQuota(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newFakeBackend(hostCPUs)
		var removeCtxErrs []error
		f.onRemove = func(ctx context.Context) error {
			removeCtxErrs = append(removeCtxErrs, ctx.Err())
			return nil
		}
		c, stop := start(t, f)

		c.Set(cpuLimit(t, 50))
		synctest.Wait()
		f.takeCalls()
		stop()
		require.Equal(t, []string{"inspect", "remove"}, f.takeCalls())
		require.Equal(t, []error{nil}, removeCtxErrs, "Remove gets a context that is not cancelled")
	})
}

func TestControllerExitRemoval(t *testing.T) {
	cases := []struct {
		name string
		// prepare sets up f before Run starts and returns the steps to run before Run stops.
		prepare    func(t *testing.T, f *fakeBackend) func(c *Controller)
		wantRemove bool
	}{
		{
			name: "cap off and nothing owned",
			prepare: func(t *testing.T, f *fakeBackend) func(c *Controller) {
				return func(c *Controller) { c.Set(capOff) }
			},
		},
		{
			name: "leftover found with the cap on",
			prepare: func(t *testing.T, f *fakeBackend) func(c *Controller) {
				f.setQuota(quotaSet(4), true)
				return func(c *Controller) { c.Set(cpuLimit(t, 50)) }
			},
			wantRemove: true,
		},
		{
			name: "leftover found, then the inspection fails",
			prepare: func(t *testing.T, f *fakeBackend) func(c *Controller) {
				f.setQuota(quotaSet(4), true)
				var failing atomic.Bool
				f.onInspect = func(context.Context) (Inspection, error) {
					if failing.Load() {
						return Inspection{}, errBackend
					}
					return f.model(), nil
				}
				return func(c *Controller) {
					c.Set(cpuLimit(t, 50))
					synctest.Wait()
					failing.Store(true)
					c.Set(cpuLimit(t, 50))
					synctest.Wait()
					failing.Store(false)
				}
			},
			wantRemove: true,
		},
		{
			name: "leftover found with the cap on, then removed with the cap off",
			prepare: func(t *testing.T, f *fakeBackend) func(c *Controller) {
				f.setQuota(quotaSet(4), true)
				return func(c *Controller) {
					c.Set(cpuLimit(t, 50))
					synctest.Wait()
					c.Set(capOff)
				}
			},
		},
		{
			name: "applied, then removed with the cap off",
			prepare: func(t *testing.T, f *fakeBackend) func(c *Controller) {
				return func(c *Controller) {
					c.Set(cpuLimit(t, 50))
					synctest.Wait()
					c.Set(capOff)
				}
			},
		},
		{
			name: "unsupported with the cap on",
			prepare: func(t *testing.T, f *fakeBackend) func(c *Controller) {
				f.setQuota(quotaSet(4), true)
				f.onInspect = func(context.Context) (Inspection, error) { return Inspection{}, errNoSystemd }
				return func(c *Controller) { c.Set(cpuLimit(t, 50)) }
			},
		},
		{
			name: "apply unsupported",
			prepare: func(t *testing.T, f *fakeBackend) func(c *Controller) {
				f.onApply = func(context.Context, float64) error { return errNoSystemd }
				return func(c *Controller) { c.Set(cpuLimit(t, 50)) }
			},
		},
		{
			name: "leftover that does not match is applied again",
			prepare: func(t *testing.T, f *fakeBackend) func(c *Controller) {
				f.setQuota(quotaSet(2), true)
				f.onApply = func(context.Context, float64) error { return errBackend }
				return func(c *Controller) { c.Set(cpuLimit(t, 50)) }
			},
			wantRemove: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := newFakeBackend(hostCPUs)
				steps := tc.prepare(t, f)
				c, stop := start(t, f)

				steps(c)
				synctest.Wait()
				f.takeCalls()
				stop()
				if tc.wantRemove {
					require.Equal(t, []string{"inspect", "remove"}, f.takeCalls())
				} else {
					require.Empty(t, f.takeCalls())
				}
			})
		})
	}
}

func TestControllerExitRemovalFailure(t *testing.T) {
	cases := []struct {
		name     string
		remove   func(ctx context.Context) error
		capOff   bool
		wantTime time.Duration
	}{
		{name: "Remove fails", remove: func(context.Context) error { return errBackend }},
		{
			name: "Remove hangs",
			remove: func(ctx context.Context) error {
				<-ctx.Done()
				return ctx.Err()
			},
			wantTime: shutdownRemoveTimeout,
		},
		{name: "Remove fails with the cap off", remove: func(context.Context) error { return errBackend }, capOff: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := newFakeBackend(hostCPUs)
				f.onRemove = tc.remove
				c, stop := start(t, f)

				c.Set(cpuLimit(t, 50))
				synctest.Wait()
				if tc.capOff {
					c.Set(capOff)
					synctest.Wait()
				}
				f.takeCalls()
				begin := time.Now()
				// stop fails the test if Run returns an error.
				stop()
				require.Equal(t, tc.wantTime, time.Since(begin))
				require.Equal(t, []string{"inspect", "remove"}, f.takeCalls())
			})
		})
	}
}

func TestControllerExitChecksQuotaBeforeRemoval(t *testing.T) {
	cases := []struct {
		name string
		// prepare sets up f before Run starts and returns the steps to run before Run stops.
		prepare   func(t *testing.T, f *fakeBackend) func(c *Controller)
		wantCalls []string
		wantQuota Quota
	}{
		{
			name: "the result of an unfinished apply is unknown",
			prepare: func(t *testing.T, f *fakeBackend) func(c *Controller) {
				f.onApply = func(ctx context.Context, cpus float64) error {
					f.setQuota(quotaSet(cpus), true)
					<-ctx.Done()
					return ctx.Err()
				}
				return func(c *Controller) { c.Set(cpuLimit(t, 50)) }
			},
			wantCalls: []string{"inspect", "remove"},
			wantQuota: quotaNone,
		},
		{
			name: "the inspection fails",
			prepare: func(t *testing.T, f *fakeBackend) func(c *Controller) {
				var failing atomic.Bool
				f.onInspect = func(context.Context) (Inspection, error) {
					if failing.Load() {
						return Inspection{}, errBackend
					}
					return f.model(), nil
				}
				return func(c *Controller) {
					c.Set(cpuLimit(t, 50))
					synctest.Wait()
					failing.Store(true)
				}
			},
			wantCalls: []string{"inspect"},
			wantQuota: quotaSet(4),
		},
		{
			name: "the quota is written after a timed out apply",
			prepare: func(t *testing.T, f *fakeBackend) func(c *Controller) {
				f.onApply = func(ctx context.Context, cpus float64) error {
					<-ctx.Done()
					return ctx.Err()
				}
				return func(c *Controller) {
					c.Set(cpuLimit(t, 50))
					time.Sleep(callTimeout)
					synctest.Wait()
					// The write lands after the check and before the retry.
					f.setQuota(quotaSet(4), true)
				}
			},
			wantCalls: []string{"inspect", "remove"},
			wantQuota: quotaNone,
		},
		{
			name: "an unsupported apply keeps the last verified quota",
			prepare: func(t *testing.T, f *fakeBackend) func(c *Controller) {
				var unsupported atomic.Bool
				f.onApply = func(ctx context.Context, cpus float64) error {
					if unsupported.Load() {
						return errNoSystemd
					}
					f.setQuota(quotaSet(cpus), true)
					return nil
				}
				return func(c *Controller) {
					c.Set(cpuLimit(t, 50))
					synctest.Wait()
					unsupported.Store(true)
					f.setQuota(quotaSet(2), true)
					c.Set(cpuLimit(t, 50))
				}
			},
			wantCalls: []string{"inspect"},
			wantQuota: quotaSet(2),
		},
		{
			name: "the quota was removed by someone else",
			prepare: func(t *testing.T, f *fakeBackend) func(c *Controller) {
				return func(c *Controller) {
					c.Set(cpuLimit(t, 50))
					synctest.Wait()
					f.setQuota(quotaNone, false)
				}
			},
			wantCalls: []string{"inspect"},
			wantQuota: quotaNone,
		},
		{
			name: "an unconfirmed quota after an unverified apply",
			prepare: func(t *testing.T, f *fakeBackend) func(c *Controller) {
				f.onApply = func(context.Context, float64) error { return errBackend }
				return func(c *Controller) {
					c.Set(cpuLimit(t, 50))
					synctest.Wait()
					f.setQuota(quotaSet(4), true)
					f.setUnconfirmed()
				}
			},
			wantCalls: []string{"inspect", "remove"},
			wantQuota: quotaNone,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := newFakeBackend(hostCPUs)
				steps := tc.prepare(t, f)
				c, stop := start(t, f)

				steps(c)
				synctest.Wait()
				f.takeCalls()
				stop()
				require.Equal(t, tc.wantCalls, f.takeCalls())
				require.Equal(t, tc.wantQuota, f.serviceQuota())
			})
		})
	}
}

func TestControllerStalePassKeepsAdoptedQuota(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newFakeBackend(hostCPUs)
		f.setQuota(quotaSet(4), true)
		release := make(chan struct{})
		f.onInspect = func(ctx context.Context) (Inspection, error) {
			if err := wait(ctx, release); err != nil {
				return Inspection{}, err
			}
			return f.model(), nil
		}
		c, stop := start(t, f)

		c.Set(cpuLimit(t, 50))
		synctest.Wait()
		c.Set(capOff)
		close(release)
		synctest.Wait()
		require.Equal(t, []string{"cpus", "inspect", "inspect", "remove"}, f.takeCalls())
		require.Equal(t, quotaNone, f.serviceQuota())

		stop()
		require.Empty(t, f.takeCalls())
	})
}

func TestControllerAdoptsQuotaFoundAfterUnsupportedApply(t *testing.T) {
	for _, capOffFirst := range []bool{true, false} {
		t.Run(fmt.Sprintf("cap off first %v", capOffFirst), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := newFakeBackend(hostCPUs)
				f.setQuota(quotaSet(4), true)
				f.setUnconfirmed()
				f.onApply = func(context.Context, float64) error {
					// The pending reload ends while Apply runs, so the quota is confirmed at the next check.
					f.setQuota(quotaSet(4), true)
					return errNoSystemd
				}
				c, stop := start(t, f)

				c.Set(cpuLimit(t, 50))
				synctest.Wait()
				require.Equal(t, []string{"cpus", "inspect", "apply 4.00", "inspect"}, f.takeCalls())

				if capOffFirst {
					c.Set(capOff)
					synctest.Wait()
				}
				stop()
				require.Equal(t, []string{"inspect", "remove"}, f.takeCalls())
				require.Equal(t, quotaNone, f.serviceQuota())
			})
		})
	}
}

func TestControllerLiftsCapWithFullQuota(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newFakeBackend(hostCPUs)
		c, stop := start(t, f)

		c.Set(cpuLimit(t, 50))
		synctest.Wait()
		f.takeCalls()

		c.Set(cpuLimit(t, 100))
		synctest.Wait()
		require.Equal(t, []string{"cpus", "inspect", "apply 8.00", "inspect"}, f.takeCalls())
		require.Equal(t, quotaSet(hostCPUs), f.serviceQuota())

		c.Set(capOff)
		time.Sleep(10 * recheckInterval)
		synctest.Wait()
		require.Equal(t, []string{"inspect", "remove"}, f.takeCalls())
		require.Equal(t, quotaNone, f.serviceQuota())

		stop()
		require.Empty(t, f.takeCalls())
	})
}

func TestControllerRechecksWhileApplied(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newFakeBackend(hostCPUs)
		c, _ := start(t, f)

		c.Set(cpuLimit(t, 50))
		synctest.Wait()
		f.takeCalls()
		want := c.Snapshot()
		requireLastUpdate(t, c)

		for range 3 {
			time.Sleep(recheckInterval - time.Millisecond)
			synctest.Wait()
			require.Empty(t, f.takeCalls())
			time.Sleep(time.Millisecond)
			synctest.Wait()
			require.Equal(t, []string{"cpus", "inspect"}, f.takeCalls())
			require.Equal(t, want, c.Snapshot())
			require.Empty(t, c.Updates(), "a recheck that changes nothing publishes nothing")
		}
	})
}

func TestControllerRecheckCorrectsChangedQuota(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newFakeBackend(hostCPUs)
		release := make(chan struct{})
		applies := 0
		f.onApply = func(ctx context.Context, cpus float64) error {
			applies++
			if applies == 2 {
				if err := wait(ctx, release); err != nil {
					return err
				}
			}
			f.setQuota(quotaSet(cpus), true)
			return nil
		}
		c, _ := start(t, f)

		c.Set(cpuLimit(t, 50))
		synctest.Wait()
		f.takeCalls()
		f.setQuota(quotaSet(6), false)

		time.Sleep(recheckInterval)
		synctest.Wait()
		require.Equal(t, StatePending, c.Snapshot().State)
		requireLastUpdate(t, c)

		close(release)
		synctest.Wait()
		require.Equal(t, []string{"cpus", "inspect", "apply 4.00", "inspect"}, f.takeCalls())
		requireSnapshot(t, Snapshot{
			State: StateApplied, Configured: cpuLimit(t, 50), TargetCPUs: 4, ActiveQuota: quotaSet(4),
			EffectiveQuota: quotaSet(4),
		}, false, c.Snapshot())
		requireLastUpdate(t, c)
	})
}

func TestControllerLowerParentQuota(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newFakeBackend(hostCPUs)
		f.setParent(quotaSet(2))
		c, _ := start(t, f)

		c.Set(cpuLimit(t, 50))
		synctest.Wait()
		require.Equal(t, []string{"cpus", "inspect", "apply 4.00", "inspect"}, f.takeCalls())
		want := Snapshot{
			State: StateApplied, Configured: cpuLimit(t, 50), TargetCPUs: 4, ActiveQuota: quotaSet(4),
			EffectiveQuota: quotaSet(2),
		}
		requireSnapshot(t, want, false, c.Snapshot())
		requireLastUpdate(t, c)
		require.True(t, isClosed(c.Ready()))

		for range 3 {
			time.Sleep(recheckInterval)
			synctest.Wait()
			require.Equal(t, []string{"cpus", "inspect"}, f.takeCalls(), "a lower parent quota does not make a write")
			requireSnapshot(t, want, false, c.Snapshot())
			require.Empty(t, c.Updates())
		}
	})
}

func TestControllerPublishesEffectiveQuotaChange(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newFakeBackend(hostCPUs)
		c, _ := start(t, f)

		c.Set(cpuLimit(t, 50))
		synctest.Wait()
		f.takeCalls()
		requireLastUpdate(t, c)

		f.setParent(quotaSet(3))
		time.Sleep(recheckInterval)
		synctest.Wait()
		require.Equal(t, []string{"cpus", "inspect"}, f.takeCalls())
		requireSnapshot(t, Snapshot{
			State: StateApplied, Configured: cpuLimit(t, 50), TargetCPUs: 4, ActiveQuota: quotaSet(4),
			EffectiveQuota: quotaSet(3),
		}, false, c.Snapshot())
		requireLastUpdate(t, c)
	})
}

func TestControllerInvalidEffectiveQuotaIsUnknown(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newFakeBackend(hostCPUs)
		f.setQuota(quotaSet(4), true)
		f.onInspect = func(context.Context) (Inspection, error) {
			return Inspection{Service: f.model().Service, Effective: quotaSet(math.NaN())}, nil
		}
		c, _ := start(t, f)

		c.Set(cpuLimit(t, 50))
		synctest.Wait()
		require.Equal(t, []string{"cpus", "inspect"}, f.takeCalls())
		requireSnapshot(t, Snapshot{
			State: StateApplied, Configured: cpuLimit(t, 50), TargetCPUs: 4, ActiveQuota: quotaSet(4),
		}, false, c.Snapshot())
	})
}

func TestControllerRecheckDoesNotDropRunningPass(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newFakeBackend(hostCPUs)
		release := make(chan struct{})
		inspects := 0
		f.onInspect = func(ctx context.Context) (Inspection, error) {
			inspects++
			if inspects == 3 {
				if err := wait(ctx, release); err != nil {
					return Inspection{}, err
				}
			}
			return f.model(), nil
		}
		c, _ := start(t, f)

		c.Set(cpuLimit(t, 50))
		synctest.Wait()
		f.takeCalls()
		f.setQuota(quotaSet(6), false)

		time.Sleep(recheckInterval)
		synctest.Wait()
		c.Set(cpuLimit(t, 50))
		close(release)
		synctest.Wait()
		// The recheck corrects the quota, then the Set runs one more check.
		require.Equal(t, []string{"cpus", "inspect", "apply 4.00", "inspect", "cpus", "inspect"}, f.takeCalls())
		require.Equal(t, StateApplied, c.Snapshot().State)
	})
}

func TestControllerRetryBackoffResets(t *testing.T) {
	t.Run("after a success", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			f := newFakeBackend(hostCPUs)
			var failing atomic.Bool
			failing.Store(true)
			f.onApply = func(_ context.Context, cpus float64) error {
				if failing.Load() {
					return errBackend
				}
				f.setQuota(quotaSet(cpus), true)
				return nil
			}
			c, _ := start(t, f)

			c.Set(cpuLimit(t, 50))
			synctest.Wait()
			f.takeCalls()
			requireApplyAfter(t, f, 5*time.Second)
			requireApplyAfter(t, f, 10*time.Second)
			failing.Store(false)
			requireApplyAfter(t, f, 20*time.Second)
			require.Equal(t, StateApplied, c.Snapshot().State)

			failing.Store(true)
			f.setQuota(quotaSet(6), false)
			requireApplyAfter(t, f, recheckInterval)
			require.Equal(t, StateDegraded, c.Snapshot().State)
			requireApplyAfter(t, f, 5*time.Second)
		})
	})
	t.Run("after a changed request", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			f := newFakeBackend(hostCPUs)
			f.onApply = func(context.Context, float64) error { return errBackend }
			c, _ := start(t, f)

			c.Set(cpuLimit(t, 50))
			synctest.Wait()
			f.takeCalls()
			requireApplyAfter(t, f, 5*time.Second)
			requireApplyAfter(t, f, 10*time.Second)

			c.Set(cpuLimit(t, 25))
			synctest.Wait()
			require.Equal(t, 1, countApplies(f.takeCalls()))
			requireApplyAfter(t, f, 5*time.Second)
		})
	})
}

// start creates a controller with b and runs it.
func start(t *testing.T, b Backend) (*Controller, func()) {
	log, _ := loggertest.New(t.Name())
	c := NewController(log, b)
	return c, run(t, c)
}

// run starts c.Run. The returned stop function cancels it and waits for Run to return.
// It also runs when the test ends.
func run(t *testing.T, c *Controller) func() {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- c.Run(ctx) }()

	var once sync.Once
	stop := func() {
		once.Do(func() {
			cancel()
			require.NoError(t, <-done)
		})
	}
	t.Cleanup(stop)
	return stop
}

func cpuLimit(t *testing.T, percent int) limits.CPULimit {
	t.Helper()
	var l limits.CPULimit
	require.NoError(t, l.Unpack(int64(percent)))
	return l
}

// wait blocks until ch is closed or ctx is done.
func wait(ctx context.Context, ch <-chan struct{}) error {
	select {
	case <-ch:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func isClosed(ch <-chan struct{}) bool {
	select {
	case <-ch:
		return true
	default:
		return false
	}
}

func countApplies(calls []string) int {
	return len(slices.DeleteFunc(calls, func(call string) bool { return !strings.HasPrefix(call, "apply ") }))
}

// requireApplyAfter checks that the next apply runs exactly d from now.
func requireApplyAfter(t *testing.T, f *fakeBackend, d time.Duration) {
	t.Helper()
	time.Sleep(d - time.Millisecond)
	synctest.Wait()
	require.Zero(t, countApplies(f.takeCalls()), "no apply before %v", d)
	time.Sleep(time.Millisecond)
	synctest.Wait()
	require.Equal(t, 1, countApplies(f.takeCalls()), "one apply after %v", d)
}

// requireCallsAfter checks that no backend call runs before d from now, and that the calls at d are want.
func requireCallsAfter(t *testing.T, f *fakeBackend, d time.Duration, want []string) {
	t.Helper()
	time.Sleep(d - time.Millisecond)
	synctest.Wait()
	require.Empty(t, f.takeCalls(), "no call before %v", d)
	time.Sleep(time.Millisecond)
	synctest.Wait()
	require.Equal(t, want, f.takeCalls(), "calls after %v", d)
}

// requireLastUpdate checks that Updates holds the current Snapshot and nothing else.
func requireLastUpdate(t *testing.T, c *Controller) {
	t.Helper()
	select {
	case s := <-c.Updates():
		require.Equal(t, c.Snapshot(), s)
	default:
		require.Fail(t, "no snapshot on Updates")
	}
}

// requireSnapshot compares got with want. It checks only whether Err is set, not its text.
func requireSnapshot(t *testing.T, want Snapshot, wantErr bool, got Snapshot) {
	t.Helper()
	if wantErr {
		require.Error(t, got.Err)
	} else {
		require.NoError(t, got.Err)
	}
	want.Err, got.Err = nil, nil
	require.Equal(t, want, got)
}
