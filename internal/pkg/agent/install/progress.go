// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package install

import (
	"fmt"
	"io"
	"strings"
)

type ProgressTracker struct {
	writer io.Writer
}

func NewProgressTracker(writer io.Writer) *ProgressTracker {
	return &ProgressTracker{
		writer: writer,
	}
}

func (pt *ProgressTracker) StepStart(msg string) {
	fmt.Fprintf(pt.writer, strings.TrimSpace(msg)+"...")
}

func (pt *ProgressTracker) StepSucceeded() {
	fmt.Fprintln(pt.writer, "DONE")
}

func (pt *ProgressTracker) StepFailed() {
	fmt.Fprintln(pt.writer, "FAILED")
}
