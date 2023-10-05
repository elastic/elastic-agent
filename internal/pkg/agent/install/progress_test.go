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

		rs := pt.Start()

		s := rs.StepStart("step 1 starting")
		s.Failed()

		rs.Failed()

		require.Equal(t, "step 1 starting... FAILED\n", string(w.buf))
	})

	t.Run("single_step_delayed_failure", func(t *testing.T) {
		w := newTestWriter()
		pt := NewProgressTracker(w)
		pt.SetTickInterval(10 * time.Millisecond) // to speed up testing
		pt.DisableRandomizedTickIntervals()

		rs := pt.Start()

		s := rs.StepStart("step 1 starting")
		time.Sleep(100 * time.Millisecond) // to simulate work being done
		s.Failed()

		rs.Failed()

		require.Regexp(t, regexp.MustCompile(`step 1 starting\.{3,}\.+ FAILED\n`), string(w.buf))
	})

	t.Run("multi_step_immediate_success", func(t *testing.T) {
		w := newTestWriter()
		pt := NewProgressTracker(w)
		pt.DisableRandomizedTickIntervals()

		rs := pt.Start()

		s := rs.StepStart("step 1 starting")
		s.Succeeded()
		s = rs.StepStart("step 2 starting")
		s.Succeeded()

		rs.Succeeded()

		require.Equal(t, "step 1 starting... DONE\nstep 2 starting... DONE\n", string(w.buf))
	})

	t.Run("multi_step_delayed_success", func(t *testing.T) {
		w := newTestWriter()
		pt := NewProgressTracker(w)
		pt.SetTickInterval(10 * time.Millisecond) // to speed up testing
		pt.DisableRandomizedTickIntervals()

		rs := pt.Start()

		s := rs.StepStart("step 1 starting")
		time.Sleep(55 * time.Millisecond) // to simulate work being done
		s.Succeeded()
		s = rs.StepStart("step 2 starting")
		time.Sleep(25 * time.Millisecond) // to simulate work being done
		s.Succeeded()

		rs.Succeeded()

		require.Regexp(t, regexp.MustCompile(`step 1 starting\.{3,}\.+ DONE\nstep 2 starting\.{3,}\.+ DONE`), string(w.buf))
	})

	t.Run("single_step_delay_after_failed", func(t *testing.T) {
		w := newTestWriter()
		pt := NewProgressTracker(w)
		pt.SetTickInterval(10 * time.Millisecond) // to speed up testing
		pt.DisableRandomizedTickIntervals()

		rs := pt.Start()

		s := rs.StepStart("step 1 starting")
		s.Failed()
		time.Sleep(15 * time.Millisecond)

		rs.Failed()

		require.Regexp(t, regexp.MustCompile(`step 1 starting.{3,} FAILED\n`), string(w.buf))

	})

	t.Run("nested_step_delayed_success", func(t *testing.T) {
		w := newTestWriter()
		pt := NewProgressTracker(w)
		pt.SetTickInterval(10 * time.Millisecond) // to speed up testing
		pt.DisableRandomizedTickIntervals()

		rs := pt.Start()

		s := rs.StepStart("step starting")
		ss := s.StepStart("substep 1 starting")
		time.Sleep(55 * time.Millisecond) // to simulate work being done
		ss.Succeeded()
		ss = s.StepStart("substep 2 starting")
		time.Sleep(25 * time.Millisecond) // to simulate work being done
		ss.Succeeded()
		s.Succeeded()

		rs.Succeeded()

		require.Regexp(t, regexp.MustCompile(`step starting\.{3,}\n   substep 1 starting\.{3,}\.+ DONE\n   substep 2 starting\.{3,}\.+ DONE\n   DONE\n`), string(w.buf))
	})
}
