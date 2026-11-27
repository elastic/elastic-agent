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
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/elastic/elastic-agent/pkg/core/logger/loggertest"
	"github.com/elastic/elastic-agent/pkg/limits"
)

const hostCPUs = 8

var (
	errBackend   = errors.New("backend failure")
	errNoSystemd = fmt.Errorf("probe: %w", &UnsupportedError{Reason: "no systemd"})
	quotaNone    = Quota{Kind: QuotaNone}
	quotaSkipped = skippedQuota()
	capOff       = limits.CPULimit{}
)

func TestControllerAppliesCap(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newFakeBackend(hostCPUs)
		c, _ := start(t, f)

		c.Set(cpuLimit(t, 50))
		synctest.Wait()
		requireSnapshot(t, Snapshot{
			State: StateApplied, Configured: cpuLimit(t, 50), TargetQuota: quotaSet(4), ActiveQuota: quotaSet(4),
			EffectiveQuota: quotaSet(4),
		}, false, c.Snapshot())
		require.Equal(t, []string{"cpus", "inspect", "apply 4.00", "inspect"}, f.takeCalls())
		require.True(t, isClosed(c.Initialized()))
		requireLastUpdate(t, c)
	})
}

func TestControllerBeforeFirstSet(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newFakeBackend(hostCPUs)
		c, stop := start(t, f)

		synctest.Wait()
		requireSnapshot(t, Snapshot{State: StateDisabled, Configured: capOff, TargetQuota: quotaNone, ActiveQuota: quotaSkipped, EffectiveQuota: quotaSkipped}, false, c.Snapshot())
		require.False(t, isClosed(c.Initialized()))
		stop()
		require.Empty(t, f.takeCalls())
	})
}

func TestControllerSkipsWriteWhenQuotaIsInPlace(t *testing.T) {
	cases := []struct {
		name        string
		logicalCPUs int
		percent     int
		active      float64
		wantCalls   []string
		wantQuota   float64
	}{
		{name: "exact", logicalCPUs: 8, percent: 50, active: 4, wantCalls: []string{"cpus", "inspect"}, wantQuota: 4},
		{name: "within tolerance", logicalCPUs: 8, percent: 50, active: 4.009, wantCalls: []string{"cpus", "inspect"}, wantQuota: 4.009},
		{
			name: "outside tolerance", logicalCPUs: 8, percent: 50, active: 4.02,
			wantCalls: []string{"cpus", "inspect", "apply 4.00", "inspect"}, wantQuota: 4,
		},
		{name: "within tolerance of a large host", logicalCPUs: 1000, percent: 1, active: 10.09, wantCalls: []string{"cpus", "inspect"}, wantQuota: 10.09},
		{
			name: "outside tolerance of a large host", logicalCPUs: 1000, percent: 1, active: 10.11,
			wantCalls: []string{"cpus", "inspect", "apply 10.00", "inspect"}, wantQuota: 10,
		},
		{name: "at the tolerance boundary", logicalCPUs: 10, percent: 11, active: 1.11, wantCalls: []string{"cpus", "inspect"}, wantQuota: 1.11},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := newFakeBackend(tc.logicalCPUs)
				f.setQuota(quotaSet(tc.active), true)
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
			State: StateApplied, Configured: cpuLimit(t, 75), TargetQuota: quotaSet(6), ActiveQuota: quotaSet(6),
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
		// The pass for 50 checked its quota after the change to 25. The pass for 25 waits for the CPU count.
		require.Equal(t, []string{"cpus", "inspect", "apply 4.00", "inspect", "cpus"}, f.takeCalls())
		require.Empty(t, c.Updates(), "the stale pass must not publish")
		requireSnapshot(t, Snapshot{
			State: StatePending, Configured: cpuLimit(t, 25), ActiveQuota: quotaSkipped, EffectiveQuota: quotaSkipped,
		}, false, c.Snapshot())

		close(releaseCount)
		synctest.Wait()
		requireSnapshot(t, Snapshot{
			State: StateApplied, Configured: cpuLimit(t, 25), TargetQuota: quotaSet(2), ActiveQuota: quotaSet(2),
			EffectiveQuota: quotaSet(2),
		}, false, c.Snapshot())
	})
}

func TestControllerStalePassLogsNothing(t *testing.T) {
	t.Run("apply", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			f := newFakeBackend(hostCPUs)
			release := make(chan struct{})
			inspects := 0
			f.onInspect = func(ctx context.Context) (Inspection, error) {
				inspects++
				if inspects == 2 {
					if err := wait(ctx, release); err != nil {
						return Inspection{}, err
					}
				}
				return f.model(), nil
			}
			c, _, logs := startWithLogs(t, f)

			c.Set(cpuLimit(t, 50))
			synctest.Wait()
			c.Set(cpuLimit(t, 25))
			close(release)
			synctest.Wait()
			require.Equal(t, []string{"cpus", "inspect", "apply 4.00", "inspect", "cpus", "inspect", "apply 2.00", "inspect"}, f.takeCalls())
			// Only the pass for 25 logs. It found the quota that the stale pass set.
			set := logs.FilterMessageSnippet("Set the CPU quota").All()
			require.Len(t, set, 1)
			require.Equal(t, "the CPU quota is 4.00 CPUs, expected 2.00 CPUs", set[0].ContextMap()["reason"])
		})
	})
	t.Run("remove", func(t *testing.T) {
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
			c, _, logs := startWithLogs(t, f)

			c.Set(cpuLimit(t, 50))
			synctest.Wait()
			c.Set(capOff)
			synctest.Wait()
			c.Set(cpuLimit(t, 50))
			close(release)
			synctest.Wait()
			require.Equal(t, StateApplied, c.Snapshot().State)
			require.Empty(t, logs.FilterMessageSnippet("Removed the CPU quota").All())
		})
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
		// The pass for the cap started, so a removal is due.
		requireSnapshot(t, Snapshot{State: StatePending, TargetQuota: quotaNone, ActiveQuota: quotaSkipped, EffectiveQuota: quotaSkipped}, false, c.Snapshot())
		close(release)
		synctest.Wait()
		// The stale pass does not check the quota. The next pass removes the quota that the Apply wrote.
		require.Equal(t, []string{"cpus", "inspect", "apply 4.00", "remove"}, f.takeCalls())
		requireSnapshot(t, Snapshot{State: StateDisabled, TargetQuota: quotaNone, ActiveQuota: quotaSkipped, EffectiveQuota: quotaSkipped}, false, c.Snapshot())
		require.Equal(t, quotaNone, f.activeQuota())
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
		require.Equal(t, []string{"remove"}, f.takeCalls(), "the failed Apply may have written a quota, so it is removed")
		time.Sleep(recheckInterval)
		synctest.Wait()
		require.Empty(t, f.takeCalls(), "the retry for the old cap stops")
		requireSnapshot(t, Snapshot{State: StateDisabled, TargetQuota: quotaNone, ActiveQuota: quotaSkipped, EffectiveQuota: quotaSkipped}, false, c.Snapshot())
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
		require.False(t, isClosed(c.Initialized()))
		c.Set(capOff)
		require.True(t, isClosed(c.Initialized()))
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
		c, _, logs := startWithLogs(t, f)

		c.Set(cpuLimit(t, 50))
		synctest.Wait()
		requireSnapshot(t, Snapshot{
			State: StateDegraded, Configured: cpuLimit(t, 50), TargetQuota: quotaSet(4), ActiveQuota: quotaNone,
			EffectiveQuota: quotaNone,
		}, true, c.Snapshot())
		require.ErrorIs(t, c.Snapshot().Err, errBackend)
		require.False(t, isClosed(c.Initialized()))
		require.Empty(t, logs.FilterMessageSnippet("recovered").All())

		time.Sleep(retryMinDelay)
		synctest.Wait()
		requireSnapshot(t, Snapshot{
			State: StateApplied, Configured: cpuLimit(t, 50), TargetQuota: quotaSet(4), ActiveQuota: quotaSet(4),
			EffectiveQuota: quotaSet(4),
		}, false, c.Snapshot())
		require.True(t, isClosed(c.Initialized()))
		require.Equal(t, []zapcore.Level{zapcore.InfoLevel}, levels(logs, "CPU limit enforcement recovered"))

		time.Sleep(recheckInterval)
		synctest.Wait()
		require.Len(t, logs.FilterMessageSnippet("recovered").All(), 1, "a recheck that finds no problem logs nothing")
	})
}

func TestControllerChecksQuotaAfterFailedApply(t *testing.T) {
	cases := []struct {
		name      string
		worked    bool
		hang      bool
		wantState State
		wantQuota Quota
	}{
		{name: "fails, write worked", worked: true, wantState: StateApplied, wantQuota: quotaSet(4)},
		{name: "fails, write did not work", wantState: StateDegraded, wantQuota: quotaNone},
		{name: "times out, write worked", worked: true, hang: true, wantState: StateApplied, wantQuota: quotaSet(4)},
		{name: "times out, write did not work", hang: true, wantState: StateDegraded, wantQuota: quotaNone},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := newFakeBackend(hostCPUs)
				f.onApply = func(ctx context.Context, cpus float64) error {
					if tc.worked {
						f.setQuota(quotaSet(cpus), true)
					}
					if !tc.hang {
						return errBackend
					}
					<-ctx.Done()
					return ctx.Err()
				}
				c, _ := start(t, f)

				c.Set(cpuLimit(t, 50))
				if tc.hang {
					synctest.Wait()
					require.Equal(t, StatePending, c.Snapshot().State)
					time.Sleep(backendCallTimeout)
				}
				synctest.Wait()
				require.Equal(t, []string{"cpus", "inspect", "apply 4.00", "inspect"}, f.takeCalls())
				requireSnapshot(t, Snapshot{
					State: tc.wantState, Configured: cpuLimit(t, 50), TargetQuota: quotaSet(4), ActiveQuota: tc.wantQuota,
					EffectiveQuota: tc.wantQuota,
				}, !tc.worked, c.Snapshot())
				require.Equal(t, tc.worked, isClosed(c.Initialized()))
				if !tc.worked {
					// The error tells both what Apply returned and what the check found.
					require.ErrorContains(t, c.Snapshot().Err, "failed to change the CPU quota")
					require.ErrorContains(t, c.Snapshot().Err, "no CPU quota is set")
				}
			})
		})
	}
}

func TestControllerJoinsApplyAndCheckFailures(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newFakeBackend(hostCPUs)
		errApply := errors.New("apply failure")
		f.onApply = func(context.Context, float64) error { return errApply }
		inspects := 0
		f.onInspect = func(context.Context) (Inspection, error) {
			inspects++
			if inspects == 2 {
				return Inspection{}, errBackend
			}
			return f.model(), nil
		}
		c, stop := start(t, f)

		c.Set(cpuLimit(t, 50))
		synctest.Wait()
		require.Equal(t, []string{"cpus", "inspect", "apply 4.00", "inspect"}, f.takeCalls())
		s := c.Snapshot()
		require.Equal(t, StateDegraded, s.State)
		require.ErrorIs(t, s.Err, errApply)
		require.ErrorIs(t, s.Err, errBackend)

		stop()
		require.Equal(t, []string{"remove"}, f.takeCalls(), "a failed Apply may have written the quota, so the controller may remove it")
	})
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
			want:      Snapshot{TargetQuota: quotaSet(4)},
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
			want:      Snapshot{TargetQuota: quotaSet(4), ActiveQuota: quotaSet(3), EffectiveQuota: quotaSet(3)},
		},
		{
			name: "inspect returns NaN",
			setup: func(f *fakeBackend) {
				f.onInspect = func(context.Context) (Inspection, error) {
					return Inspection{Active: quotaSet(math.NaN()), Effective: quotaSet(4)}, nil
				}
			},
			wantCalls: []string{"cpus", "inspect"},
			want:      Snapshot{TargetQuota: quotaSet(4)},
		},
		{
			name: "inspect returns Inf",
			setup: func(f *fakeBackend) {
				f.onInspect = func(context.Context) (Inspection, error) {
					return Inspection{Active: quotaSet(math.Inf(1)), Effective: quotaSet(4)}, nil
				}
			},
			wantCalls: []string{"cpus", "inspect"},
			want:      Snapshot{TargetQuota: quotaSet(4)},
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
				require.False(t, isClosed(c.Initialized()))
			})
		})
	}
}

func TestControllerCallInspectChecksResult(t *testing.T) {
	other := Quota{Kind: "other", CPUs: 2}
	cases := []struct {
		name          string
		active        Quota
		effective     Quota
		wantErr       string
		wantActive    Quota
		wantEffective Quota
	}{
		{name: "valid", active: quotaSet(4), effective: quotaSet(2), wantActive: quotaSet(4), wantEffective: quotaSet(2)},
		{name: "active unknown", active: Quota{}, effective: quotaSet(2), wantErr: `invalid CPU quota kind ""`},
		{name: "active skipped", active: quotaSkipped, effective: quotaSet(2), wantErr: `invalid CPU quota kind "skipped"`},
		{name: "active other kind", active: other, effective: quotaSet(2), wantErr: `invalid CPU quota kind "other"`},
		{name: "active NaN", active: quotaSet(math.NaN()), effective: quotaSet(2), wantErr: "invalid CPU quota NaN"},
		{name: "active Inf", active: quotaSet(math.Inf(1)), effective: quotaSet(2), wantErr: "invalid CPU quota +Inf"},
		{name: "active -Inf", active: quotaSet(math.Inf(-1)), effective: quotaSet(2), wantErr: "invalid CPU quota -Inf"},
		{name: "active zero", active: quotaSet(0), effective: quotaSet(2), wantErr: "invalid CPU quota 0"},
		{name: "active negative", active: quotaSet(-1), effective: quotaSet(2), wantErr: "invalid CPU quota -1"},
		{name: "active none with CPUs", active: Quota{Kind: QuotaNone, CPUs: 3}, effective: quotaSet(2), wantActive: quotaNone, wantEffective: quotaSet(2)},
		{name: "effective unknown", active: quotaSet(4), effective: Quota{}, wantActive: quotaSet(4), wantEffective: Quota{}},
		{name: "effective skipped", active: quotaSet(4), effective: quotaSkipped, wantActive: quotaSet(4), wantEffective: Quota{}},
		{name: "effective other kind", active: quotaSet(4), effective: other, wantActive: quotaSet(4), wantEffective: Quota{}},
		{name: "effective NaN", active: quotaSet(4), effective: quotaSet(math.NaN()), wantActive: quotaSet(4), wantEffective: Quota{}},
		{name: "effective Inf", active: quotaSet(4), effective: quotaSet(math.Inf(1)), wantActive: quotaSet(4), wantEffective: Quota{}},
		{name: "effective -Inf", active: quotaSet(4), effective: quotaSet(math.Inf(-1)), wantActive: quotaSet(4), wantEffective: Quota{}},
		{name: "effective zero", active: quotaSet(4), effective: quotaSet(0), wantActive: quotaSet(4), wantEffective: Quota{}},
		{name: "effective negative", active: quotaSet(4), effective: quotaSet(-1), wantActive: quotaSet(4), wantEffective: Quota{}},
		{name: "effective none with CPUs", active: quotaSet(4), effective: Quota{Kind: QuotaNone, CPUs: 3}, wantActive: quotaSet(4), wantEffective: quotaNone},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeBackend(hostCPUs)
			f.onInspect = func(context.Context) (Inspection, error) {
				return Inspection{Active: tc.active, Effective: tc.effective}, nil
			}
			log, _ := loggertest.New(t.Name())
			c := NewController(log, f)

			ins, err := c.callInspect(context.Background())
			if tc.wantErr != "" {
				require.EqualError(t, err, tc.wantErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, Inspection{Active: tc.wantActive, Effective: tc.wantEffective}, ins)
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
			TargetQuota:    quotaSet(2),
			ActiveQuota:    quotaSet(4),
			EffectiveQuota: quotaSet(4),
		}, false, c.Snapshot())

		close(release)
		synctest.Wait()
		requireSnapshot(t, Snapshot{
			State: StateApplied, Configured: cpuLimit(t, 25), TargetQuota: quotaSet(2), ActiveQuota: quotaSet(2),
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
			State: StateApplied, Configured: cpuLimit(t, 50), TargetQuota: quotaSet(4), ActiveQuota: quotaSet(4),
			EffectiveQuota: quotaSet(4),
		}, false, c.Snapshot())
	})
}

func TestControllerCapOffRemovesQuotaItSet(t *testing.T) {
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
			State: StatePending, TargetQuota: quotaNone, ActiveQuota: quotaSet(4), EffectiveQuota: quotaSet(4),
		}, false, c.Snapshot())
		close(release)
		synctest.Wait()
		require.Equal(t, []string{"remove"}, f.takeCalls())
		requireSnapshot(t, Snapshot{State: StateDisabled, TargetQuota: quotaNone, ActiveQuota: quotaSkipped, EffectiveQuota: quotaSkipped}, false, c.Snapshot())
		require.Equal(t, quotaNone, f.activeQuota())
		requireLastUpdate(t, c)

		time.Sleep(10 * recheckInterval)
		synctest.Wait()
		require.Empty(t, f.takeCalls(), "no recheck with the cap off")
		require.Empty(t, c.Updates())

		stop()
		require.Empty(t, f.takeCalls(), "the removed quota is not removed again")
	})
}

func TestControllerCapOffRemovesQuotaWhateverItsValue(t *testing.T) {
	cases := []struct {
		name string
		// prepare sets up f before Run starts and returns the steps to run before the cap goes off.
		prepare   func(t *testing.T, f *fakeBackend) func(c *Controller)
		wantQuota Quota
	}{
		{
			name: "a quota changed by someone else",
			prepare: func(t *testing.T, f *fakeBackend) func(c *Controller) {
				return func(c *Controller) {
					c.Set(cpuLimit(t, 50))
					synctest.Wait()
					f.setQuota(quotaSet(2), true)
				}
			},
			wantQuota: quotaNone,
		},
		{
			name: "a quota that the agent does not hold",
			prepare: func(t *testing.T, f *fakeBackend) func(c *Controller) {
				return func(c *Controller) {
					c.Set(cpuLimit(t, 50))
					synctest.Wait()
					f.setQuota(quotaSet(4), false)
				}
			},
			// Remove clears only the agent's own mechanism, so this quota stays.
			wantQuota: quotaSet(4),
		},
		{
			name: "a verified quota whose override is deleted with a pending reload",
			prepare: func(t *testing.T, f *fakeBackend) func(c *Controller) {
				return func(c *Controller) {
					c.Set(cpuLimit(t, 50))
					synctest.Wait()
					// Until the reload runs, the system still enforces the old quota. Remove completes the reload.
					f.setQuota(quotaSet(4), true)
				}
			},
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
			wantQuota: quotaNone,
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
			// Remove clears only the agent's own mechanism, so this quota stays.
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
				require.Equal(t, []string{"remove"}, f.takeCalls())
				requireSnapshot(t, Snapshot{State: StateDisabled, TargetQuota: quotaNone, ActiveQuota: quotaSkipped, EffectiveQuota: quotaSkipped}, false, c.Snapshot())

				stop()
				require.Empty(t, f.takeCalls(), "the controller may no longer remove the quota, so the exit leaves it alone")
				require.Equal(t, tc.wantQuota, f.activeQuota())
			})
		})
	}
}

func TestControllerCapOffRemovalRetries(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newFakeBackend(hostCPUs)
		var failing atomic.Bool
		f.onRemove = func(context.Context) error {
			if failing.Load() {
				return errBackend
			}
			f.setQuota(quotaNone, false)
			return nil
		}
		c, stop, logs := startWithLogs(t, f)

		c.Set(cpuLimit(t, 50))
		synctest.Wait()
		f.takeCalls()
		failing.Store(true)
		c.Set(capOff)
		synctest.Wait()
		require.Equal(t, []string{"remove"}, f.takeCalls())
		requireSnapshot(t, Snapshot{State: StateDegraded, TargetQuota: quotaNone}, true, c.Snapshot())
		require.ErrorIs(t, c.Snapshot().Err, errBackend)
		require.Equal(t, []zapcore.Level{zapcore.WarnLevel}, levels(logs, "Failed to remove the CPU quota"))
		require.Empty(t, logs.FilterMessageSnippet("Failed to enforce").All())

		for _, seconds := range []int{5, 10, 20, 40, 60, 60} {
			requireCallsAfter(t, f, time.Duration(seconds)*time.Second, []string{"remove"})
		}
		failing.Store(false)
		requireCallsAfter(t, f, retryMaxDelay, []string{"remove"})
		requireSnapshot(t, Snapshot{State: StateDisabled, TargetQuota: quotaNone, ActiveQuota: quotaSkipped, EffectiveQuota: quotaSkipped}, false, c.Snapshot())
		require.Equal(t, quotaNone, f.activeQuota())
		wantLevels := []zapcore.Level{zapcore.WarnLevel}
		for range 6 {
			wantLevels = append(wantLevels, zapcore.DebugLevel)
		}
		require.Equal(t, wantLevels, levels(logs, "Failed to remove the CPU quota"))
		require.Equal(t, []zapcore.Level{zapcore.InfoLevel}, levels(logs, "Removed the CPU quota"))
		require.Empty(t, logs.FilterMessageSnippet("recovered").All())

		time.Sleep(10 * recheckInterval)
		synctest.Wait()
		stop()
		require.Empty(t, f.takeCalls())
	})
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
				State: StateApplied, Configured: cpuLimit(t, 50), TargetQuota: quotaSet(4), ActiveQuota: quotaSet(4),
				EffectiveQuota: quotaSet(4),
			}, false, c.Snapshot())
			time.Sleep(10 * recheckInterval)
			synctest.Wait()
			require.NotContains(t, f.takeCalls(), "remove")
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
			require.Equal(t, []string{"remove", "cpus", "inspect", "apply 2.00", "inspect"}, f.takeCalls())
			requireSnapshot(t, Snapshot{
				State: StateApplied, Configured: cpuLimit(t, 25), TargetQuota: quotaSet(2), ActiveQuota: quotaSet(2),
				EffectiveQuota: quotaSet(2),
			}, false, c.Snapshot())
			requireLastUpdate(t, c)
			require.Equal(t, quotaSet(2), f.activeQuota())
		})
	})
}

// The pass for the newest cap-off request has nothing to remove, but it must still show the cap as off.
func TestControllerStaleRemovalSettlesState(t *testing.T) {
	cases := []struct {
		name string
		// removed is what the blocked Remove does after release is closed.
		removed   func(f *fakeBackend) error
		wantQuota Quota
	}{
		{
			name: "the removal succeeds",
			removed: func(f *fakeBackend) error {
				f.setQuota(quotaNone, false)
				return nil
			},
			wantQuota: quotaNone,
		},
		{
			name:      "unsupported",
			removed:   func(*fakeBackend) error { return errNoSystemd },
			wantQuota: quotaSet(4),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := newFakeBackend(hostCPUs)
				release := make(chan struct{})
				f.onRemove = func(ctx context.Context) error {
					if err := wait(ctx, release); err != nil {
						return err
					}
					return tc.removed(f)
				}
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
				require.Equal(t, []string{"remove"}, f.takeCalls())
				requireSnapshot(t, Snapshot{State: StateDisabled, TargetQuota: quotaNone, ActiveQuota: quotaSkipped, EffectiveQuota: quotaSkipped}, false, c.Snapshot())
				requireLastUpdate(t, c)

				time.Sleep(10 * recheckInterval)
				synctest.Wait()
				stop()
				require.Empty(t, f.takeCalls())
				require.Equal(t, tc.wantQuota, f.activeQuota())
			})
		})
	}
}

func TestControllerCapOffRemovalUnsupported(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newFakeBackend(hostCPUs)
		f.onRemove = func(context.Context) error { return errNoSystemd }
		c, stop := start(t, f)

		c.Set(cpuLimit(t, 50))
		synctest.Wait()
		f.takeCalls()
		c.Set(capOff)
		synctest.Wait()
		require.Equal(t, []string{"remove"}, f.takeCalls())
		requireSnapshot(t, Snapshot{State: StateDisabled, TargetQuota: quotaNone, ActiveQuota: quotaSkipped, EffectiveQuota: quotaSkipped}, false, c.Snapshot())

		time.Sleep(10 * recheckInterval)
		synctest.Wait()
		stop()
		require.Empty(t, f.takeCalls(), "unsupported is not retried")
	})
}

func TestControllerCapOffAtStart(t *testing.T) {
	cases := []struct {
		name      string
		active    Quota
		agentHeld bool
	}{
		{name: "no quota", active: quotaNone},
		{name: "quota set by someone else", active: quotaSet(2)},
		{name: "agent leftover", active: quotaSet(2), agentHeld: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := newFakeBackend(hostCPUs)
				f.setQuota(tc.active, tc.agentHeld)
				c, stop := start(t, f)

				c.Set(capOff)
				require.True(t, isClosed(c.Initialized()))
				time.Sleep(10 * recheckInterval)
				synctest.Wait()
				requireSnapshot(t, Snapshot{State: StateDisabled, TargetQuota: quotaNone, ActiveQuota: quotaSkipped, EffectiveQuota: quotaSkipped}, false, c.Snapshot())

				stop()
				require.Empty(t, f.takeCalls())
				require.Equal(t, tc.active, f.activeQuota())
			})
		})
	}
}

func TestControllerCapOffAfterUnsupportedRemovesThenSkipsQuotas(t *testing.T) {
	for _, removeUnsupported := range []bool{false, true} {
		t.Run(fmt.Sprintf("removeUnsupported=%t", removeUnsupported), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := newFakeBackend(hostCPUs)
				f.setQuota(quotaSet(2), false)
				f.onApply = func(context.Context, float64) error { return errNoSystemd }
				if removeUnsupported {
					f.onRemove = func(context.Context) error { return errNoSystemd }
				}
				c, _ := start(t, f)

				c.Set(cpuLimit(t, 50))
				synctest.Wait()
				s := c.Snapshot()
				require.Equal(t, StateUnsupported, s.State)
				require.Equal(t, quotaSet(2), s.ActiveQuota)
				require.Equal(t, quotaSet(2), s.EffectiveQuota)
				f.takeCalls()

				c.Set(capOff)
				requireSnapshot(t, Snapshot{
					State: StatePending, TargetQuota: quotaNone, ActiveQuota: quotaSet(2), EffectiveQuota: quotaSet(2),
				}, false, c.Snapshot())
				synctest.Wait()
				require.Equal(t, []string{"remove"}, f.takeCalls())
				requireSnapshot(t, Snapshot{State: StateDisabled, TargetQuota: quotaNone, ActiveQuota: quotaSkipped, EffectiveQuota: quotaSkipped}, false, c.Snapshot())
			})
		})
	}
}

func TestControllerCapOffMakesNoBackendCalls(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newFakeBackend(hostCPUs)
		c, stop := start(t, f)

		c.Set(capOff)
		require.True(t, isClosed(c.Initialized()))
		synctest.Wait()
		requireLastUpdate(t, c)
		for range 4 {
			c.Set(capOff)
			synctest.Wait()
			time.Sleep(recheckInterval)
		}
		synctest.Wait()
		requireSnapshot(t, Snapshot{State: StateDisabled, TargetQuota: quotaNone, ActiveQuota: quotaSkipped, EffectiveQuota: quotaSkipped}, false, c.Snapshot())
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
			want:      Snapshot{State: StateUnsupported, TargetQuota: quotaSet(4), Reason: "no systemd"},
		},
		{
			name:      "apply unsupported",
			setup:     func(f *fakeBackend) { f.onApply = func(context.Context, float64) error { return errNoSystemd } },
			wantCalls: []string{"cpus", "inspect", "apply 4.00", "inspect"},
			want: Snapshot{
				State: StateUnsupported, TargetQuota: quotaSet(4), ActiveQuota: quotaNone, EffectiveQuota: quotaNone, Reason: "no systemd",
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
			want:      Snapshot{State: StateUnsupported, TargetQuota: quotaSet(4), Reason: "no systemd"},
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
			want:      Snapshot{State: StateUnsupported, TargetQuota: quotaSet(4), Reason: "no systemd"},
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
			want:      Snapshot{State: StateUnsupported, TargetQuota: quotaSet(4), Reason: "no systemd"},
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
			want:      Snapshot{State: StateUnsupported, TargetQuota: quotaSet(4), Reason: "no systemd"},
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
				require.True(t, isClosed(c.Initialized()))

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
			name:  "CPU count",
			setup: func(f *fakeBackend) { f.onLogicalCPUs = func(ctx context.Context) (int, error) { return 0, hang(ctx) } },
			// The pass for the cap started, so Run removes the quota when it stops.
			wantCalls: []string{"cpus", "remove"},
			want:      Snapshot{State: StatePending, ActiveQuota: quotaSkipped, EffectiveQuota: quotaSkipped},
		},
		{
			name: "inspect",
			setup: func(f *fakeBackend) {
				f.onInspect = func(ctx context.Context) (Inspection, error) { return Inspection{}, hang(ctx) }
			},
			wantCalls: []string{"cpus", "inspect", "remove"},
			want:      Snapshot{State: StatePending, ActiveQuota: quotaSkipped, EffectiveQuota: quotaSkipped},
		},
		{
			name:      "apply",
			setup:     func(f *fakeBackend) { f.onApply = func(ctx context.Context, _ float64) error { return hang(ctx) } },
			wantCalls: []string{"cpus", "inspect", "apply 4.00", "remove"},
			want:      Snapshot{State: StatePending, ActiveQuota: quotaSkipped, EffectiveQuota: quotaSkipped},
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
		require.True(t, isClosed(c.Initialized()))
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
			wantPending: Snapshot{State: StatePending, TargetQuota: quotaSet(2), ActiveQuota: quotaNone, EffectiveQuota: quotaNone},
			wantDone:    Snapshot{State: StateApplied, TargetQuota: quotaSet(2), ActiveQuota: quotaSet(2), EffectiveQuota: quotaSet(2)},
		},
		{
			name:        "cap off",
			wantPending: Snapshot{State: StatePending, TargetQuota: quotaNone, ActiveQuota: quotaNone, EffectiveQuota: quotaNone},
			wantDone:    Snapshot{State: StateDisabled, TargetQuota: quotaNone, ActiveQuota: quotaSkipped, EffectiveQuota: quotaSkipped},
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
				f.onRemove = func(ctx context.Context) error { return wait(ctx, release) }
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

func TestControllerLogsFailureOncePerRequest(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newFakeBackend(hostCPUs)
		f.onLogicalCPUs = func(context.Context) (int, error) { return 0, errBackend }
		c, _, logs := startWithLogs(t, f)

		c.Set(cpuLimit(t, 50))
		synctest.Wait()
		time.Sleep(retryMinDelay)
		synctest.Wait()
		require.Equal(t, []zapcore.Level{zapcore.WarnLevel, zapcore.DebugLevel}, levels(logs, "Failed to enforce the CPU limit"))

		// The error text stays the same, but a new request forgets the old failure.
		c.Set(cpuLimit(t, 25))
		synctest.Wait()
		require.Equal(t, []zapcore.Level{zapcore.WarnLevel, zapcore.DebugLevel, zapcore.WarnLevel}, levels(logs, "Failed to enforce the CPU limit"))
	})
}

func TestControllerLogsUnsupportedOncePerReason(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newFakeBackend(hostCPUs)
		var reason atomic.Value
		reason.Store("no systemd")
		f.onApply = func(context.Context, float64) error {
			return &UnsupportedError{Reason: reason.Load().(string)}
		}
		c, _, logs := startWithLogs(t, f)

		c.Set(cpuLimit(t, 50))
		synctest.Wait()
		c.Set(cpuLimit(t, 50))
		synctest.Wait()
		reason.Store("cgroup v1")
		c.Set(cpuLimit(t, 50))
		synctest.Wait()
		c.Set(cpuLimit(t, 50))
		synctest.Wait()
		require.Equal(t, 4, countApplies(f.takeCalls()))
		var reasons []any
		for _, e := range logs.FilterMessageSnippet("not supported").All() {
			reasons = append(reasons, e.ContextMap()["reason"])
		}
		require.Equal(t, []any{"no systemd", "cgroup v1"}, reasons)
	})
}

func TestControllerRecheckFollowsLogicalCPUCount(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newFakeBackend(hostCPUs)
		c, _ := start(t, f)

		c.Set(cpuLimit(t, 50))
		synctest.Wait()
		f.takeCalls()
		requireLastUpdate(t, c)

		f.setLogicalCPUs(4)
		time.Sleep(recheckInterval)
		synctest.Wait()
		require.Equal(t, []string{"cpus", "inspect", "apply 2.00", "inspect"}, f.takeCalls())
		requireSnapshot(t, Snapshot{
			State: StateApplied, Configured: cpuLimit(t, 50), TargetQuota: quotaSet(2), ActiveQuota: quotaSet(2),
			EffectiveQuota: quotaSet(2),
		}, false, c.Snapshot())
		requireLastUpdate(t, c)

		time.Sleep(recheckInterval)
		synctest.Wait()
		require.Equal(t, []string{"cpus", "inspect"}, f.takeCalls())
	})
}

func TestControllerRecheckFindsUnsupported(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newFakeBackend(hostCPUs)
		var unsupported atomic.Bool
		f.onInspect = func(context.Context) (Inspection, error) {
			if unsupported.Load() {
				return Inspection{}, errNoSystemd
			}
			return f.model(), nil
		}
		c, stop := start(t, f)

		c.Set(cpuLimit(t, 50))
		synctest.Wait()
		require.Equal(t, StateApplied, c.Snapshot().State)
		f.takeCalls()

		unsupported.Store(true)
		time.Sleep(recheckInterval)
		synctest.Wait()
		require.Equal(t, []string{"cpus", "inspect"}, f.takeCalls())
		requireSnapshot(t, Snapshot{
			State: StateUnsupported, Configured: cpuLimit(t, 50), TargetQuota: quotaSet(4), Reason: "no systemd",
		}, false, c.Snapshot())

		time.Sleep(10 * recheckInterval)
		synctest.Wait()
		require.Empty(t, f.takeCalls(), "unsupported is not rechecked")

		stop()
		require.Equal(t, []string{"remove"}, f.takeCalls(), "an unsupported check does not stop the removal on exit")
	})
}

func TestControllerSameValueSetDuringRetryWait(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newFakeBackend(hostCPUs)
		f.onApply = func(context.Context, float64) error { return errBackend }
		c, _ := start(t, f)

		c.Set(cpuLimit(t, 50))
		synctest.Wait()
		require.Equal(t, 1, countApplies(f.takeCalls()))

		time.Sleep(2 * time.Second)
		synctest.Wait()
		require.Empty(t, f.takeCalls())
		c.Set(cpuLimit(t, 50))
		require.Equal(t, StateDegraded, c.Snapshot().State, "the same value keeps the failure")
		synctest.Wait()
		require.Equal(t, 1, countApplies(f.takeCalls()), "the pass runs at once")
		require.Equal(t, StateDegraded, c.Snapshot().State)

		requireApplyAfter(t, f, 10*time.Second)
		require.Equal(t, StateDegraded, c.Snapshot().State)
	})
}

func TestControllerAppliesAgainWhenEnforcedQuotaDiffers(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newFakeBackend(hostCPUs)
		f.setQuota(quotaSet(3), true)
		c, _ := start(t, f)

		c.Set(cpuLimit(t, 50))
		synctest.Wait()
		require.Equal(t, []string{"cpus", "inspect", "apply 4.00", "inspect"}, f.takeCalls())
		requireSnapshot(t, Snapshot{
			State: StateApplied, Configured: cpuLimit(t, 50), TargetQuota: quotaSet(4), ActiveQuota: quotaSet(4),
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
			State: StateApplied, Configured: cpuLimit(t, 50), TargetQuota: quotaSet(4), ActiveQuota: quotaSet(4),
			EffectiveQuota: quotaSet(4),
		}, false, c.Snapshot())

		time.Sleep(recheckInterval)
		synctest.Wait()
		require.Equal(t, []string{"cpus", "inspect"}, f.takeCalls(), "the recheck runs again")
	})
}

func TestControllerCapOnAfterRemovalShowsNoOldQuota(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newFakeBackend(hostCPUs)
		c, _ := start(t, f)

		c.Set(cpuLimit(t, 50))
		synctest.Wait()
		c.Set(capOff)
		synctest.Wait()
		require.Equal(t, []string{"cpus", "inspect", "apply 4.00", "inspect", "remove"}, f.takeCalls())

		f.onLogicalCPUs = func(context.Context) (int, error) { return 0, errBackend }
		c.Set(cpuLimit(t, 25))
		requireSnapshot(t, Snapshot{
			State: StatePending, Configured: cpuLimit(t, 25), TargetQuota: quotaSet(2), ActiveQuota: quotaSkipped,
			EffectiveQuota: quotaSkipped,
		}, false, c.Snapshot())
		synctest.Wait()
		requireSnapshot(t, Snapshot{
			State: StateDegraded, Configured: cpuLimit(t, 25), TargetQuota: quotaSet(2),
		}, true, c.Snapshot())
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

func TestControllerExitRemovesQuotaItSet(t *testing.T) {
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
		require.Equal(t, []string{"remove"}, f.takeCalls())
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
			name: "cap off and no quota to remove",
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
				f.onRemove = func(context.Context) error { return errNoSystemd }
				return func(c *Controller) { c.Set(cpuLimit(t, 50)) }
			},
			wantRemove: true,
		},
		{
			name: "apply unsupported",
			prepare: func(t *testing.T, f *fakeBackend) func(c *Controller) {
				f.onApply = func(context.Context, float64) error { return errNoSystemd }
				f.onRemove = func(context.Context) error { return errNoSystemd }
				return func(c *Controller) { c.Set(cpuLimit(t, 50)) }
			},
			wantRemove: true,
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
				log, logs := loggertest.New(t.Name())
				c := NewController(log, f)
				stop := run(t, c)

				steps(c)
				synctest.Wait()
				f.takeCalls()
				stop()
				if tc.wantRemove {
					require.Equal(t, []string{"remove"}, f.takeCalls())
				} else {
					require.Empty(t, f.takeCalls())
				}
				require.Empty(t, logs.FilterMessageSnippet("when stopping").All(), "an unsupported removal is not logged")
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
				stop()
				require.Equal(t, tc.wantTime, time.Since(begin))
				require.Equal(t, []string{"remove"}, f.takeCalls())
			})
		})
	}
}

func TestControllerExitRemovesQuotaSetAfterApply(t *testing.T) {
	cases := []struct {
		name string
		// prepare sets up f before Run starts and returns the steps to run before Run stops.
		prepare   func(t *testing.T, f *fakeBackend) func(c *Controller)
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
			wantQuota: quotaNone,
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
					time.Sleep(backendCallTimeout)
					synctest.Wait()
					// The quota is written after the check and before the retry.
					f.setQuota(quotaSet(4), true)
				}
			},
			wantQuota: quotaNone,
		},
		{
			name: "a changed quota is removed after an unsupported apply",
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
			wantQuota: quotaNone,
		},
		{
			name: "a failed apply that wrote nothing",
			prepare: func(t *testing.T, f *fakeBackend) func(c *Controller) {
				f.onApply = func(context.Context, float64) error { return errBackend }
				return func(c *Controller) { c.Set(cpuLimit(t, 50)) }
			},
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
				require.Equal(t, []string{"remove"}, f.takeCalls())
				require.Equal(t, tc.wantQuota, f.activeQuota())
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
		require.Equal(t, []string{"cpus", "inspect", "remove"}, f.takeCalls())
		require.Equal(t, quotaNone, f.activeQuota())

		stop()
		require.Empty(t, f.takeCalls())
	})
}

func TestControllerAdoptsQuotaFoundAfterUnsupportedApply(t *testing.T) {
	for _, capOffFirst := range []bool{true, false} {
		t.Run(fmt.Sprintf("cap off first %v", capOffFirst), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := newFakeBackend(hostCPUs)
				// The agent's own override asks for 4 CPUs, but its reload is pending, so the system still enforces 2.
				f.setQuota(quotaSet(2), true)
				f.onApply = func(context.Context, float64) error {
					// The reload ends while Apply runs, so the next check finds the target quota.
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
				require.Equal(t, []string{"remove"}, f.takeCalls())
				require.Equal(t, quotaNone, f.activeQuota())
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
		require.Equal(t, quotaSet(hostCPUs), f.activeQuota())

		c.Set(capOff)
		time.Sleep(10 * recheckInterval)
		synctest.Wait()
		require.Equal(t, []string{"remove"}, f.takeCalls())
		require.Equal(t, quotaNone, f.activeQuota())

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
			requireLastUpdate(t, c)
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
			State: StateApplied, Configured: cpuLimit(t, 50), TargetQuota: quotaSet(4), ActiveQuota: quotaSet(4),
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
			State: StateApplied, Configured: cpuLimit(t, 50), TargetQuota: quotaSet(4), ActiveQuota: quotaSet(4),
			EffectiveQuota: quotaSet(2),
		}
		requireSnapshot(t, want, false, c.Snapshot())
		requireLastUpdate(t, c)
		require.True(t, isClosed(c.Initialized()))

		for range 3 {
			time.Sleep(recheckInterval)
			synctest.Wait()
			require.Equal(t, []string{"cpus", "inspect"}, f.takeCalls(), "a lower parent quota does not make a write")
			requireSnapshot(t, want, false, c.Snapshot())
			requireLastUpdate(t, c)
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
			State: StateApplied, Configured: cpuLimit(t, 50), TargetQuota: quotaSet(4), ActiveQuota: quotaSet(4),
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
			return Inspection{Active: f.model().Active, Effective: quotaSet(math.NaN())}, nil
		}
		c, _ := start(t, f)

		c.Set(cpuLimit(t, 50))
		synctest.Wait()
		require.Equal(t, []string{"cpus", "inspect"}, f.takeCalls())
		requireSnapshot(t, Snapshot{
			State: StateApplied, Configured: cpuLimit(t, 50), TargetQuota: quotaSet(4), ActiveQuota: quotaSet(4),
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

func start(t *testing.T, b Backend) (*Controller, func()) {
	c, stop, _ := startWithLogs(t, b)
	return c, stop
}

func startWithLogs(t *testing.T, b Backend) (*Controller, func(), *observer.ObservedLogs) {
	log, logs := loggertest.New(t.Name())
	c := NewController(log, b)
	return c, run(t, c), logs
}

// levels returns the levels of the logs whose message contains snippet.
func levels(logs *observer.ObservedLogs, snippet string) []zapcore.Level {
	var got []zapcore.Level
	for _, e := range logs.FilterMessageSnippet(snippet).All() {
		got = append(got, e.Level)
	}
	return got
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
