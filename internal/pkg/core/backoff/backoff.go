// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package backoff

import "time"

// Backoff defines the interface for backoff strategies.
type Backoff interface {
	// Wait blocks for a duration of time governed by the backoff strategy.
	Wait() bool

	// NextWait returns the duration of the next call to Wait().
	NextWait() time.Duration

	// Reset resets the backoff duration to an initial value governed by the backoff strategy.
	Reset()
}
