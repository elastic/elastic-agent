// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package hostinfo

import (
	"context"
	"fmt"
	"reflect"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/elastic/elastic-agent/pkg/core/logger"
	"github.com/elastic/elastic-agent/pkg/features"
)

// FetchFunc gathers the host information.
type FetchFunc func(context.Context) (Info, error)

// Watcher keeps the latest host information, so it can be shared without doing the I/O for every use. While it runs,
// it fetches the host information every check interval, and whenever the feature flags, which include the FQDN
// feature, are applied. If a fetch fails, it keeps the last host information it got.
type Watcher struct {
	log      *logger.Logger
	interval time.Duration
	fetch    FetchFunc

	// fetchMu serializes fetches, so concurrent Get calls don't fetch the host information more than once.
	fetchMu sync.Mutex

	mu      sync.Mutex
	info    *Info
	changed chan struct{}
	// synced is closed when the host information is stored for the first time.
	synced chan struct{}
}

// NewWatcher returns a Watcher that fetches the host information every interval, or every DefaultCheckInterval if
// interval isn't positive.
func NewWatcher(log *logger.Logger, interval time.Duration) *Watcher {
	return NewWatcherWithFetcher(log, interval, func(context.Context) (Info, error) {
		return Fetch(log)
	})
}

// NewWatcherWithFetcher returns a Watcher like NewWatcher, which gets the host information from fetch instead of
// Fetch.
func NewWatcherWithFetcher(log *logger.Logger, interval time.Duration, fetch FetchFunc) *Watcher {
	if interval <= 0 {
		interval = DefaultCheckInterval
	}
	return &Watcher{
		log:      log,
		interval: interval,
		fetch:    fetch,
		changed:  make(chan struct{}),
		synced:   make(chan struct{}),
	}
}

// Run keeps the host information up to date until ctx is done.
func (w *Watcher) Run(ctx context.Context) error {
	// Create the trigger before the first fetch, so an FQDN feature change during it isn't missed.
	trigger, err := newTrigger(w.interval)
	if err != nil {
		return err
	}
	defer trigger.stop()

	for {
		w.fetchMu.Lock()
		_, err := w.fetchLocked(ctx)
		w.fetchMu.Unlock()
		if err != nil {
			w.log.Warnf("Failed fetching latest host information: %s", err)
		}

		if err := trigger.wait(ctx); err != nil {
			return err
		}
	}
}

// Get returns the latest host information. If none has been fetched yet, for example because Run hasn't fetched it
// yet or the fetches failed, Get fetches it.
func (w *Watcher) Get(ctx context.Context) (Info, error) {
	if info, ok := w.latest(); ok {
		return info, nil
	}

	w.fetchMu.Lock()
	defer w.fetchMu.Unlock()
	// Another fetch may have finished while we waited for the lock.
	if info, ok := w.latest(); ok {
		return info, nil
	}
	return w.fetchLocked(ctx)
}

// Synced returns a channel that is closed by the first successful fetch, either in Run or in Get, and stays closed.
// After that, Get returns the stored host information without fetching it. Synced doesn't fetch, so if nothing does,
// the channel is never closed.
func (w *Watcher) Synced() <-chan struct{} {
	return w.synced
}

// Changed returns a channel that is closed when the host information changes, including when it's fetched for the
// first time. Call Changed before Get, so a change between the two isn't missed. To wait for host information that
// may already be there, use Synced instead.
func (w *Watcher) Changed() <-chan struct{} {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.changed
}

func (w *Watcher) latest() (Info, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.info == nil {
		return Info{}, false
	}
	return w.info.clone(), true
}

// fetchLocked fetches the host information and stores it. The caller must hold fetchMu.
func (w *Watcher) fetchLocked(ctx context.Context) (Info, error) {
	info, err := w.fetch(ctx)
	if err != nil {
		return Info{}, err
	}

	w.mu.Lock()
	defer w.mu.Unlock()
	if w.info == nil {
		close(w.synced)
	}
	if w.info == nil || !reflect.DeepEqual(*w.info, info) {
		w.info = &info
		close(w.changed)
		w.changed = make(chan struct{})
	}
	return w.info.clone(), nil
}

// clone returns a copy of i that doesn't share memory with it, so callers can't modify the stored host information.
func (i Info) clone() Info {
	i.IPs = slices.Clone(i.IPs)
	i.MACs = slices.Clone(i.MACs)
	return i
}

// triggerCount makes the FQDN feature callback ID of each trigger unique.
var triggerCount atomic.Uint64

// trigger tells when the host information should be fetched again: when the check interval has passed since the
// last check, and when the feature flags, which include the FQDN feature, are applied.
type trigger struct {
	interval    time.Duration
	callbackID  string
	fqdnChanged chan struct{}
}

func newTrigger(interval time.Duration) (*trigger, error) {
	t := &trigger{
		interval:    interval,
		callbackID:  fmt.Sprintf("hostinfo-trigger-%d", triggerCount.Add(1)),
		fqdnChanged: make(chan struct{}, 1),
	}
	if err := features.AddFQDNOnChangeCallback(t.onFQDNChange, t.callbackID); err != nil {
		return nil, fmt.Errorf("failed to watch the FQDN feature: %w", err)
	}
	return t, nil
}

// onFQDNChange runs while the feature flags are locked, so it only signals wait. It's called whenever the feature
// flags are applied, even if the FQDN feature didn't change.
func (t *trigger) onFQDNChange(_, _ bool) {
	select {
	case t.fqdnChanged <- struct{}{}:
	default:
	}
}

// wait blocks until the host information should be fetched again. It returns ctx.Err() if ctx is done first.
func (t *trigger) wait(ctx context.Context) error {
	timer := time.NewTimer(t.interval)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.fqdnChanged:
	case <-timer.C:
	}
	return nil
}

func (t *trigger) stop() {
	features.RemoveFQDNOnChangeCallback(t.callbackID)
}
