// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package testcontext

import (
	"context"
	"testing"
	"time"
)

// WithDeadline returns a context with a deadline. The deadline is the earliest
// of either the provided 'deadline' or t.Deadline().
func WithDeadline(
	t *testing.T,
	parent context.Context,
	deadline time.Time) (context.Context, context.CancelFunc) {
	if d, ok := t.Deadline(); ok {
		deadline = d
	}
	ctx, cancel := context.WithDeadline(parent, deadline)
	return ctx, cancel
}

// WithTimeout returns a context with a deadline calculated from the provided
// timeout duration. It is the equivalent of calling WithDeadline with the
// deadline specified as time.Now() + timeout.
func WithTimeout(
	t *testing.T,
	parentCtx context.Context,
	timeout time.Duration,
) (context.Context, context.CancelFunc) {
	return WithDeadline(t, parentCtx, time.Now().Add(timeout))
}
