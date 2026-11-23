// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package downloads

import (
	"context"
	"time"

	backoff "github.com/cenkalti/backoff/v7"
)

// timeoutFactor a multiplier for the max timeout when doing backoff retries.
// It can be overridden by TIMEOUT_FACTOR env var
var timeoutFactor = 3

func init() {
	timeoutFactor = getEnvInteger("TIMEOUT_FACTOR", timeoutFactor)
}

// getExponentialBackoff returns a preconfigured exponential backoff instance.
// The maxElapsedTime is used by retryOperation and is no longer set on the
// backoff struct itself (MaxElapsedTime was removed from ExponentialBackOff in
// backoff/v7 and is now a RetryOption).
func getExponentialBackoff(_ time.Duration) *backoff.ExponentialBackOff {
	exp := backoff.NewExponentialBackOff()
	exp.InitialInterval = 10 * time.Second
	exp.RandomizationFactor = 0.5
	exp.Multiplier = 2.0
	exp.MaxInterval = 30 * time.Second
	return exp
}

// retryOperation runs f with the given BackOff policy, stopping after maxElapsedTime.
// It unwraps the RetryError returned by backoff/v7 so callers receive the
// original operation error, preserving the behaviour of the old RetryNotify API.
func retryOperation(f func() error, b backoff.BackOff, maxElapsedTime time.Duration) error {
	opts := []backoff.RetryOption{backoff.WithBackOff(b)}
	if maxElapsedTime > 0 {
		opts = append(opts, backoff.WithMaxElapsedTime(maxElapsedTime))
	}
	_, err := backoff.Retry(context.Background(), func() (struct{}, error) {
		return struct{}{}, f()
	}, opts...)
	if err != nil {
		if re := backoff.AsRetryError(err); re != nil && re.LastErr != nil {
			return re.LastErr
		}
		return err
	}
	return nil
}
