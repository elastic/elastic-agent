// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package hostinfo

import (
	"context"
	"errors"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/internal/pkg/config"
	testlogger "github.com/elastic/elastic-agent/pkg/core/logger/loggertest"
	"github.com/elastic/elastic-agent/pkg/features"
)

type fetchResult struct {
	info Info
	err  error
}

// fakeFetcher returns results in order, repeating the last one, and counts the calls.
type fakeFetcher struct {
	mu      sync.Mutex
	results []fetchResult
	calls   int
}

func (f *fakeFetcher) fetch(context.Context) (Info, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	r := f.results[min(f.calls, len(f.results)-1)]
	f.calls++
	return r.info, r.err
}

func (f *fakeFetcher) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func newTestWatcher(t *testing.T, interval time.Duration, results ...fetchResult) (*Watcher, *fakeFetcher) {
	log, _ := testlogger.New(t.Name())
	f := &fakeFetcher{results: results}
	return NewWatcherWithFetcher(log, interval, f.fetch), f
}

// runWatcher runs w until the returned function is called.
func runWatcher(t *testing.T, w *Watcher) func() {
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error)
	go func() { done <- w.Run(ctx) }()
	return func() {
		cancel()
		assert.ErrorIs(t, <-done, context.Canceled)
	}
}

func TestWatcherGetWithoutRun(t *testing.T) {
	w, f := newTestWatcher(t, time.Minute,
		fetchResult{err: errors.New("fetch failed")},
		fetchResult{info: Info{Hostname: "a"}},
		fetchResult{info: Info{Hostname: "b"}},
	)

	_, err := w.Get(t.Context())
	require.Error(t, err, "Get returns the error of the fetch when there's no host information")

	info, err := w.Get(t.Context())
	require.NoError(t, err)
	assert.Equal(t, Info{Hostname: "a"}, info, "Get fetches again after a failed fetch")

	info, err = w.Get(t.Context())
	require.NoError(t, err)
	assert.Equal(t, Info{Hostname: "a"}, info, "Get returns the stored host information")
	assert.Equal(t, 2, f.callCount())
}

func TestWatcherGetReturnsCopy(t *testing.T) {
	w, _ := newTestWatcher(t, time.Minute, fetchResult{info: Info{IPs: []string{"10.0.0.1"}}})

	info, err := w.Get(t.Context())
	require.NoError(t, err)
	info.IPs[0] = "modified"

	info, err = w.Get(t.Context())
	require.NoError(t, err)
	assert.Equal(t, []string{"10.0.0.1"}, info.IPs)
}

func TestWatcherRunUpdates(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		a := Info{Hostname: "a"}
		b := Info{Hostname: "b"}
		w, f := newTestWatcher(t, time.Minute,
			fetchResult{info: a},
			fetchResult{err: errors.New("fetch failed")},
			fetchResult{info: a},
			fetchResult{info: b},
		)
		start := time.Now()
		changed := w.Changed()
		stop := runWatcher(t, w)

		<-changed
		assert.Zero(t, time.Since(start), "the first fetch happens immediately")
		changed = w.Changed()
		info, err := w.Get(t.Context())
		require.NoError(t, err)
		assert.Equal(t, a, info)

		// The failed fetch keeps the stored information, and fetching the same information again isn't a change.
		<-changed
		assert.Equal(t, 3*time.Minute, time.Since(start))
		info, err = w.Get(t.Context())
		require.NoError(t, err)
		assert.Equal(t, b, info)

		// Nothing changes anymore.
		changed = w.Changed()
		time.Sleep(10*time.Minute + 30*time.Second)
		select {
		case <-changed:
			t.Fatal("unexpected change")
		default:
		}
		stop()
		assert.Equal(t, 14, f.callCount())
	})
}

func TestWatcherDefaultCheckInterval(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w, _ := newTestWatcher(t, 0,
			fetchResult{info: Info{Hostname: "a"}},
			fetchResult{info: Info{Hostname: "b"}},
		)
		start := time.Now()
		changed := w.Changed()
		stop := runWatcher(t, w)

		<-changed
		changed = w.Changed()
		<-changed
		assert.Equal(t, DefaultCheckInterval, time.Since(start))
		stop()
	})
}

func TestWatcherFeatureFlags(t *testing.T) {
	setFQDN := func(t *testing.T, enabled bool) {
		require.NoError(t, features.Apply(config.MustNewConfigFrom(map[string]any{
			"agent.features.fqdn.enabled": enabled,
		})))
	}
	setFQDN(t, false)
	t.Cleanup(func() { setFQDN(t, false) })

	synctest.Test(t, func(t *testing.T) {
		w, f := newTestWatcher(t, time.Hour,
			fetchResult{info: Info{Hostname: "host"}},
			fetchResult{info: Info{Hostname: "host"}},
			fetchResult{info: Info{Hostname: "Host.Example.com"}},
		)
		start := time.Now()
		changed := w.Changed()
		stop := runWatcher(t, w)
		<-changed
		changed = w.Changed()

		// Applying the feature flags fetches the host information even if the FQDN feature doesn't change, but
		// it's only a change if the host information changed.
		setFQDN(t, false)
		synctest.Wait()
		assert.Equal(t, 2, f.callCount())
		select {
		case <-changed:
			t.Fatal("unexpected change")
		default:
		}

		setFQDN(t, true)
		<-changed
		assert.Zero(t, time.Since(start))
		info, err := w.Get(t.Context())
		require.NoError(t, err)
		assert.Equal(t, "Host.Example.com", info.Hostname)
		stop()
	})
}

func TestWatcherSynced(t *testing.T) {
	t.Run("already_synced", func(t *testing.T) {
		w, f := newTestWatcher(t, time.Minute, fetchResult{info: Info{Hostname: "a"}})
		_, err := w.Get(t.Context())
		require.NoError(t, err)

		select {
		case <-w.Synced():
		default:
			t.Fatal("Synced isn't closed after the host information was fetched")
		}
		info, err := w.Get(t.Context())
		require.NoError(t, err)
		assert.Equal(t, Info{Hostname: "a"}, info)
		assert.Equal(t, 1, f.callCount(), "Get returns the stored host information once synced")
	})

	t.Run("waits_for_run", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			w, f := newTestWatcher(t, time.Minute,
				fetchResult{err: errors.New("fetch failed")},
				fetchResult{info: Info{Hostname: "a"}},
				fetchResult{info: Info{Hostname: "b"}},
			)
			start := time.Now()
			stop := runWatcher(t, w)

			<-w.Synced()
			assert.Equal(t, time.Minute, time.Since(start), "Synced waits past a failed fetch for a successful one")
			info, err := w.Get(t.Context())
			require.NoError(t, err)
			assert.Equal(t, Info{Hostname: "a"}, info)

			// Synced stays closed when the host information changes.
			time.Sleep(time.Minute)
			synctest.Wait()
			select {
			case <-w.Synced():
			default:
				t.Fatal("Synced isn't closed after the host information changed")
			}
			stop()
			assert.Equal(t, 3, f.callCount())
		})
	})

	t.Run("not_synced", func(t *testing.T) {
		w, f := newTestWatcher(t, time.Minute, fetchResult{info: Info{Hostname: "a"}})
		select {
		case <-w.Synced():
			t.Fatal("Synced is closed before the host information was fetched")
		default:
		}
		assert.Zero(t, f.callCount(), "Synced doesn't fetch")
	})
}
