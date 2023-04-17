// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package fleet

import "time"

// Scheduler is a simple interface that encapsulate the scheduling logic, this is useful if you want to
// test asynchronous code in a synchronous way.
type Scheduler interface {
	WaitTick() <-chan time.Time
	Stop()
}
