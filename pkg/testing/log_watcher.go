// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package testing

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"
)

var _ Logger = &LogWatcher{}

// LogWatcher wraps actual logger and watches for occurrences of strings
type LogWatcher struct {
	activeWatches map[string]bool
	wrapped       Logger

	watchesLock sync.Mutex
}

// NewLogWatcher returns watches initialised with watches and underlying logger
func NewLogWatcher(wrappedLogger Logger, watches ...string) *LogWatcher {
	activeWatches := make(map[string]bool)
	for _, w := range watches {
		activeWatches[w] = false
	}

	return &LogWatcher{
		wrapped:       wrappedLogger,
		activeWatches: activeWatches,
	}
}

// Log logs the arguments.
func (l *LogWatcher) Log(args ...any) {
	l.wrapped.Log(args...)
	line := fmt.Sprintln(args...)
	l.checkLine(line)
}

// Logf logs the formatted arguments.
func (l *LogWatcher) Logf(format string, args ...any) {
	l.wrapped.Logf(format, args...)
	line := fmt.Sprintf(format, args...)
	l.checkLine(line)
}

// KeyOccured return true in case key was hit before
func (l *LogWatcher) KeyOccured(key string) bool {
	return l.keysOccured(key)
}

// WaitForKeys waits for all keys to occur in a log stream.
func (l *LogWatcher) WaitForKeys(ctx context.Context, timeout, interval time.Duration, keys ...string) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	t := time.NewTicker(interval)
	defer t.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			if l.keysOccured(keys...) {
				return nil
			}
		}
	}
}

func (l *LogWatcher) checkLine(line string) {
	l.watchesLock.Lock()
	defer l.watchesLock.Unlock()

	var removeKeys []string
	for k := range l.activeWatches {
		if strings.Contains(line, k) {
			removeKeys = append(removeKeys, k)
		}
	}

	for _, k := range removeKeys {
		delete(l.activeWatches, k)
	}

}
func (l *LogWatcher) keysOccured(keys ...string) bool {
	l.watchesLock.Lock()
	defer l.watchesLock.Unlock()

	for _, k := range keys {
		if _, found := l.activeWatches[k]; found {
			return false
		}
	}
	return true
}
