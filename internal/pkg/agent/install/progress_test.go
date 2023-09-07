// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package install

import (
	"regexp"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type testWriter struct {
	buf []byte
}

func newTestWriter() *testWriter {
	return &testWriter{
		buf: []byte{},
	}
}

func (tw *testWriter) Write(p []byte) (int, error) {
	tw.buf = append(tw.buf, p...)
	return len(p), nil
}

func TestProgress(t *testing.T) {
	t.Run("single_step_immediate_failure", func(t *testing.T) {
		w := newTestWriter()
		pt := NewProgressTracker(w)

		pt.Start()

		pt.StepStart("step 1 starting")
		pt.StepFailed()

		pt.Stop()

		require.Equal(t, "step 1 starting... FAILED\n", string(w.buf))
	})

	t.Run("single_step_delayed_failure", func(t *testing.T) {
		w := newTestWriter()
		pt := NewProgressTracker(w)
		pt.SetTickInterval(10 * time.Millisecond) // to speed up testing
		pt.DisableRandomizedTickIntervals()

		pt.Start()

		pt.StepStart("step 1 starting")
		time.Sleep(15 * time.Millisecond) // to simulate work being done
		pt.StepFailed()

		pt.Stop()

		require.Regexp(t, regexp.MustCompile(`step 1 starting\.{3}\.+ FAILED\n`), string(w.buf))
	})

	t.Run("multi_step_immediate_success", func(t *testing.T) {
		w := newTestWriter()
		pt := NewProgressTracker(w)
		pt.DisableRandomizedTickIntervals()

		pt.Start()

		pt.StepStart("step 1 starting")
		pt.StepSucceeded()
		pt.StepStart("step 2 starting")
		pt.StepSucceeded()

		pt.Stop()

		require.Equal(t, "step 1 starting... DONE\nstep 2 starting... DONE\n", string(w.buf))
	})

	t.Run("multi_step_delayed_success", func(t *testing.T) {
		w := newTestWriter()
		pt := NewProgressTracker(w)
		pt.SetTickInterval(10 * time.Millisecond) // to speed up testing
		pt.DisableRandomizedTickIntervals()

		pt.Start()

		pt.StepStart("step 1 starting")
		time.Sleep(55 * time.Millisecond) // to simulate work being done
		pt.StepSucceeded()
		pt.StepStart("step 2 starting")
		time.Sleep(25 * time.Millisecond) // to simulate work being done
		pt.StepSucceeded()

		pt.Stop()

		require.Regexp(t, regexp.MustCompile(`step 1 starting\.{3}\.+ DONE\nstep 2 starting\.{3}\.+ DONE`), string(w.buf))
	})

	t.Run("single_step_delay_after_failed", func(t *testing.T) {
		w := newTestWriter()
		pt := NewProgressTracker(w)
		pt.SetTickInterval(10 * time.Millisecond) // to speed up testing
		pt.DisableRandomizedTickIntervals()

		pt.Start()

		pt.StepStart("step 1 starting")
		pt.StepFailed()
		time.Sleep(15 * time.Millisecond)

		pt.Stop()

		require.Equal(t, "step 1 starting... FAILED\n", string(w.buf))

	})
}
