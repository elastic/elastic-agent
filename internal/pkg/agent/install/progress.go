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
	step     *progressTrackerStep
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
	prefix := " "
	if pts.substeps {
		prefix = pts.prefix + "   "
	}
	if !pts.rootstep {
		pts.tracker.printf("%sDONE\n", prefix)
	}
	pts.finalizeFunc()
}

// Failed step has failed.
func (pts *progressTrackerStep) Failed() {
	prefix := " "
	if pts.substeps {
		prefix = pts.prefix + "   "
	}
	if !pts.rootstep {
		pts.tracker.printf("%sFAILED\n", prefix)
	}
	pts.finalizeFunc()
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
	s := newProgressTrackerStep(pts.tracker, prefix, func() {
		pts.step = nil
	})
	pts.step = s
	return s
}

func (pts *progressTrackerStep) tick() {
	if pts.step != nil {
		pts.step.tick()
		return
	}
	if !pts.rootstep {
		pts.tracker.printf(".")
	}
}

type ProgressTracker struct {
	writer io.Writer

	tickInterval          time.Duration
	randomizeTickInterval bool

	step *progressTrackerStep
	mu   sync.Mutex
	stop chan struct{}
}

func NewProgressTracker(writer io.Writer) *ProgressTracker {
	return &ProgressTracker{
		writer:                writer,
		tickInterval:          200 * time.Millisecond,
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

func (pt *ProgressTracker) Start() ProgressTrackerStep {
	timer := time.NewTimer(pt.calculateTickInterval())
	go func() {
		defer timer.Stop()
		for {
			select {
			case <-pt.stop:
				return
			case <-timer.C:
				if pt.step != nil {
					pt.step.tick()
				}
				timer = time.NewTimer(pt.calculateTickInterval())
			}
		}
	}()

	s := newProgressTrackerStep(pt, "", func() {
		pt.step = nil
		pt.stop <- struct{}{}
	})
	s.rootstep = true // is the root step
	pt.step = s
	return s
}

func (pt *ProgressTracker) printf(format string, a ...any) {
	pt.mu.Lock()
	defer pt.mu.Unlock()
	_, _ = fmt.Fprintf(pt.writer, format, a...)
}

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
