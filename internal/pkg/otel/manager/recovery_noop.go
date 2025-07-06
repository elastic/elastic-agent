// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package manager

import "time"

type recoveryNoop struct {
}

// newRestarterNoop returns a noop recovery timer
func newRestarterNoop() *recoveryNoop {
	return &recoveryNoop{}
}

// IsStopped returns always true
func (r *recoveryNoop) IsStopped() bool {
	return true
}

// Stop has no effect on the noop recovery timer
func (r *recoveryNoop) Stop() {
}

// ResetInitial has no effect on noop the recovery timer
func (r *recoveryNoop) ResetInitial() time.Duration {
	return 0
}

// C returns always nil
func (r *recoveryNoop) C() <-chan time.Time {
	return nil
}

// ResetNext has no effect on the noop recovery timer
func (r *recoveryNoop) ResetNext() time.Duration {
	return 0
}
