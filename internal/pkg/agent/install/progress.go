// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package install

import (
	"fmt"
	"io"
	"math"
	"strings"
	"sync"
	"time"

	"golang.org/x/exp/rand"
)

// ProgressTrackerStep is a currently running step.
//
// A step can produce a sub-step that is a step that is part of another step.
type ProgressTrackerStep interface {
	// Succeeded step is done and successful.
	Succeeded()
	// Failed step has failed.
	Failed()
	// StepStart creates a new step.
	StepStart(msg string) ProgressTrackerStep
}

type progressTrackerStep struct {
	tracker *ProgressTracker
	prefix  string

	finalizeFunc func()

	rootstep bool
	substeps bool
	mu       sync.Mutex
	step     *progressTrackerStep
	// marks that either Succeeded() or Failed() has been called,
	// and the tracker is completed. This is here so we can sync state despite tick() being called arbitrarily from a timer.
	// Should only be called from inside a mutex lock,
	// so the state can properly be synced between tick() and other methods
	completed bool
}

func newProgressTrackerStep(tracker *ProgressTracker, prefix string, finalizeFunc func()) *progressTrackerStep {
	return &progressTrackerStep{
		tracker:      tracker,
		prefix:       prefix,
		finalizeFunc: finalizeFunc,
	}
}

// Succeeded step is done and successful.
func (pts *progressTrackerStep) Succeeded() {
	// calling finalizeFunc outside a mutex prevents
	// this from being a truly atomic method, but
	// it's too easy for a mutex to get passed to the callback func and create a deadlock.
	pts.finalizeFunc()
	pts.mu.Lock()
	defer pts.mu.Unlock()
	pts.step = nil

	prefix := " "
	if pts.substeps {
		prefix = pts.prefix + "   "
	}
	if !pts.rootstep {
		pts.tracker.printf("%sDONE\n", prefix)
	}
	// mark as done before unlocking
	pts.completed = true
}

// Failed step has failed.
func (pts *progressTrackerStep) Failed() {
	pts.finalizeFunc()
	pts.mu.Lock()
	defer pts.mu.Unlock()
	pts.step = nil

	prefix := " "
	if pts.substeps {
		prefix = pts.prefix + "   "
	}
	if !pts.rootstep {
		pts.tracker.printf("%sFAILED\n", prefix)
	}
	// mark as done before unlocking
	pts.completed = true
}

// StepStart creates a new step.
func (pts *progressTrackerStep) StepStart(msg string) ProgressTrackerStep {
	prefix := pts.prefix
	if !pts.rootstep {
		prefix += "   "
		if !pts.substeps {
			prefix = "\n" + prefix
			pts.substeps = true
		}
	}
	pts.tracker.printf("%s%s...", prefix, strings.TrimSpace(msg))
	s := newProgressTrackerStep(pts.tracker, prefix, func() {})
	pts.setStep(s)
	return s
}

// setStep sets the current sub-step for the tracker
func (pts *progressTrackerStep) setStep(step *progressTrackerStep) {
	pts.mu.Lock()
	defer pts.mu.Unlock()
	pts.step = step
}

// tick iterates the tracker with a ".", traveling down to the last sub-tracker to do so.
func (pts *progressTrackerStep) tick() {
	pts.mu.Lock()
	defer pts.mu.Unlock()
	step := pts.step
	if step != nil {
		step.tick()
		return
	}
	if !pts.rootstep {
		// check completed state while we have the mutex
		if !pts.completed {
			pts.tracker.printf(".")
		}
	}
}

type ProgressTracker struct {
	writer io.Writer

	tickInterval          time.Duration
	randomizeTickInterval bool

	step        *progressTrackerStep
	writerMutex sync.Mutex
	stepMutex   sync.Mutex
	stop        chan struct{}
}

// NewProgressTracker returns a new root tracker with the given writer
func NewProgressTracker(writer io.Writer) *ProgressTracker {
	return &ProgressTracker{
		writer:                writer,
		tickInterval:          200 * time.Millisecond,
		randomizeTickInterval: true,
		stop:                  make(chan struct{}),
	}
}

// SetTickInterval sets the tracker tick interval
func (pt *ProgressTracker) SetTickInterval(d time.Duration) {
	pt.tickInterval = d
}

// DisableRandomizedTickIntervals disables randomizing the tick interval
func (pt *ProgressTracker) DisableRandomizedTickIntervals() {
	pt.randomizeTickInterval = false
}

// Start the root tracker
func (pt *ProgressTracker) Start() ProgressTrackerStep {
	timer := time.NewTimer(pt.calculateTickInterval())
	go func() {
		defer timer.Stop()
		for {
			select {
			case <-pt.stop:
				return
			case <-timer.C:
				step := pt.getStep()
				if step != nil {
					step.tick()
				}
				timer = time.NewTimer(pt.calculateTickInterval())
			}
		}
	}()

	s := newProgressTrackerStep(pt, "", func() {
		// callback here is what actually does the stopping
		pt.setStep(nil)
		pt.stop <- struct{}{}
	})
	s.rootstep = true // is the root step
	pt.setStep(s)
	return s
}

// printf the given statement to the tracker writer
func (pt *ProgressTracker) printf(format string, a ...any) {
	pt.writerMutex.Lock()
	defer pt.writerMutex.Unlock()
	_, _ = fmt.Fprintf(pt.writer, format, a...)
}

// getStep returns the substep
func (pt *ProgressTracker) getStep() *progressTrackerStep {
	pt.stepMutex.Lock()
	defer pt.stepMutex.Unlock()
	return pt.step
}

// setStep sets the substep
func (pt *ProgressTracker) setStep(step *progressTrackerStep) {
	pt.stepMutex.Lock()
	defer pt.stepMutex.Unlock()
	pt.step = step
}

// calculateTickInterval returns the tick interval
func (pt *ProgressTracker) calculateTickInterval() time.Duration {
	if !pt.randomizeTickInterval {
		return pt.tickInterval
	}

	// Randomize interval between 65% and 250% of configured interval
	// to make it look like the progress is non-linear. :)
	floor := int64(math.Floor(float64(pt.tickInterval.Milliseconds()) * 0.65))
	ceiling := int64(math.Floor(float64(pt.tickInterval.Milliseconds()) * 2.5))

	randomDuration := rand.Int63() % ceiling
	if randomDuration < floor {
		randomDuration = floor
	}

	return time.Duration(randomDuration) * time.Millisecond
}
