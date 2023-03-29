// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package fleet

import "time"

type clock interface {
	Now() time.Time
}

type stdlibClock struct{}

func (stdlibClock) Now() time.Time {
	return time.Now()
}
