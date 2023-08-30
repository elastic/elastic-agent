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
)

type ProgressTracker struct {
	writer               io.Writer
	progressTickDuration time.Duration
	stepInProgress       bool
	mu                   sync.RWMutex
	stop                 chan struct{}
}

func NewProgressTracker(writer io.Writer) *ProgressTracker {
	return &ProgressTracker{
		writer:               writer,
		progressTickDuration: 100 * time.Millisecond,
		stop:                 make(chan struct{}),
	}
}

func (pt *ProgressTracker) SetProgressTickDuration(d time.Duration) {
	pt.progressTickDuration = d
}

func (pt *ProgressTracker) Start() {
	ticker := time.NewTicker(pt.progressTickDuration)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-pt.stop:
				return
			case <-ticker.C:
				pt.mu.RLock()
				if pt.stepInProgress {
					pt.writer.Write([]byte("."))
				}
				pt.mu.RUnlock()
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
