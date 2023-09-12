// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

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
