// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package install

import (
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"golang.org/x/exp/rand"
)

type ProgressTracker struct {
	writer io.Writer

	tickInterval          time.Duration
	randomizeTickInterval bool

	stepInProgress bool
	mu             sync.RWMutex
	stop           chan struct{}
}

func NewProgressTracker(writer io.Writer) *ProgressTracker {
	return &ProgressTracker{
		writer:                writer,
		tickInterval:          100 * time.Millisecond,
		randomizeTickInterval: true,
		stop:                  make(chan struct{}),
	}
}

func (pt *ProgressTracker) SetTickInterval(d time.Duration) {
	pt.tickInterval = d
}

func (pt *ProgressTracker) DisableRandomizedTickIntervals() {
	pt.randomizeTickInterval = false
}

func (pt *ProgressTracker) Start() {
	timer := time.NewTimer(pt.calculateTickInterval())
	go func() {
		defer timer.Stop()
		for {
			select {
			case <-pt.stop:
				return
			case <-timer.C:
				pt.mu.RLock()
				if pt.stepInProgress {
					pt.writer.Write([]byte("."))
				}
				pt.mu.RUnlock()

				timer = time.NewTimer(pt.calculateTickInterval())
			}
		}
	}()
}

func (pt *ProgressTracker) StepStart(msg string) {
	pt.mu.Lock()
	defer pt.mu.Unlock()

	pt.stepInProgress = true
	fmt.Fprintf(pt.writer, strings.TrimSpace(msg)+"...")
}

func (pt *ProgressTracker) StepSucceeded() {
	pt.mu.Lock()
	defer pt.mu.Unlock()

	fmt.Fprintln(pt.writer, " DONE")
	pt.stepInProgress = false
}

func (pt *ProgressTracker) StepFailed() {
	pt.mu.Lock()
	defer pt.mu.Unlock()

	fmt.Fprintln(pt.writer, " FAILED")
	pt.stepInProgress = false
}

func (pt *ProgressTracker) Stop() {
	pt.stop <- struct{}{}
}

func (pt *ProgressTracker) calculateTickInterval() time.Duration {
	if !pt.randomizeTickInterval {
		return pt.tickInterval
	}

	return time.Duration(rand.Float64() * 2 * float64(pt.tickInterval.Milliseconds()))
}
