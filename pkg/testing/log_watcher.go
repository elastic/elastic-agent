// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package testing

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"
)

var _ Logger = &LogWatcher{}

// LogWatcher wraps actual logger and watches for occurrences of strings
type LogWatcher struct {
	activeWatches map[string]bool
	wrapped       Logger
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
	o := l.keysOccured(key)
	fmt.Fprintf(os.Stderr, "KeyOccured check %q:%v %#v", key, o, l.activeWatches)
	return o
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
	for k := range l.activeWatches {
		fmt.Fprintf(os.Stderr, "Checking %q against line %q", k, line)
		if strings.Contains(line, k) {
			l.activeWatches[k] = true
		}
	}

}
func (l *LogWatcher) keysOccured(keys ...string) bool {
	allFound := true
	for _, k := range keys {
		if v, found := l.activeWatches[k]; found {
			allFound = allFound && v
		} else {
			allFound = false
		}
	}
	return allFound
}
