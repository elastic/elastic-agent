// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package install

import (
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
		pt.SetProgressTickDuration(10 * time.Millisecond) // to speed up testing

		pt.Start()

		pt.StepStart("step 1 starting")
		time.Sleep(22 * time.Millisecond) // to simulate work being done
		pt.StepFailed()

		pt.Stop()

		require.Equal(t, "step 1 starting..... FAILED\n", string(w.buf))
	})

	t.Run("multi_step_immediate_success", func(t *testing.T) {
		w := newTestWriter()
		pt := NewProgressTracker(w)

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
		pt.SetProgressTickDuration(10 * time.Millisecond) // to speed up testing

		pt.Start()

		pt.StepStart("step 1 starting")
		time.Sleep(52 * time.Millisecond) // to simulate work being done
		pt.StepSucceeded()
		pt.StepStart("step 2 starting")
		time.Sleep(12 * time.Millisecond) // to simulate work being done
		pt.StepSucceeded()

		pt.Stop()

		require.Equal(t, "step 1 starting........ DONE\nstep 2 starting.... DONE\n", string(w.buf))
	})

	t.Run("single_step_delay_after_success", func(t *testing.T) {
		w := newTestWriter()
		pt := NewProgressTracker(w)
		pt.SetProgressTickDuration(10 * time.Millisecond) // to speed up testing

		pt.Start()

		pt.StepStart("step 1 starting")
		pt.StepFailed()
		time.Sleep(22 * time.Millisecond) // to simulate work being done

		pt.Stop()

		require.Equal(t, "step 1 starting... FAILED\n", string(w.buf))

	})
}
