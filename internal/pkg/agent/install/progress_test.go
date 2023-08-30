// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package install

import (
	"testing"

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

		pt.StepStart("step 1 starting")
		pt.StepFailed()

		require.Equal(t, "step 1 starting... FAILED\n", string(w.buf))
	})

	t.Run("multi_step_success", func(t *testing.T) {
		w := newTestWriter()
		pt := NewProgressTracker(w)

		pt.StepStart("step 1 starting")
		pt.StepSucceeded()
		pt.StepStart("step 2 starting")
		pt.StepSucceeded()

		require.Equal(t, "step 1 starting... DONE\nstep 2 starting... DONE\n", string(w.buf))
	})
}
