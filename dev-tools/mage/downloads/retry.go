// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package downloads

import (
	"time"

	backoff "github.com/cenkalti/backoff/v4"
)

// timeoutFactor a multiplier for the max timeout when doing backoff retries.
// It can be overridden by TIMEOUT_FACTOR env var
var timeoutFactor = 3

func init() {
	timeoutFactor = getEnvInteger("TIMEOUT_FACTOR", timeoutFactor)
}

// getExponentialBackoff returns a preconfigured exponential backoff instance
func getExponentialBackoff(elapsedTime time.Duration) *backoff.ExponentialBackOff {
	var (
		initialInterval     = 10 * time.Second
		randomizationFactor = 0.5
		multiplier          = 2.0
		maxInterval         = 30 * time.Second
		maxElapsedTime      = elapsedTime
	)

	exp := backoff.NewExponentialBackOff()
	exp.InitialInterval = initialInterval
	exp.RandomizationFactor = randomizationFactor
	exp.Multiplier = multiplier
	exp.MaxInterval = maxInterval
	exp.MaxElapsedTime = maxElapsedTime

	return exp
}
