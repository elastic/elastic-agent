// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package dispatcher

import (
	"fmt"
	"time"
)

var ErrNoRetry = fmt.Errorf("no retry attempts remaining")

type retryConfig struct {
	steps []time.Duration
}

func defaultRetryConfig() *retryConfig {
	return &retryConfig{
		steps: []time.Duration{time.Minute, 5 * time.Minute, 10 * time.Minute, 15 * time.Minute, 30 * time.Minute, time.Hour},
	}
}

func (r *retryConfig) GetWait(step int) (time.Duration, error) {
	if step < 0 || step >= len(r.steps) {
		return time.Duration(0), ErrNoRetry
	}
	return r.steps[step], nil
}
