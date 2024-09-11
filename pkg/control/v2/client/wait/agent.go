// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package wait

import (
	"context"
	"errors"
	"time"
)

// ForAgent waits for the agent daemon to be able to be communicated with.
func ForAgent(ctx context.Context, timeout time.Duration) error {
	if timeout == 0 {
		timeout = 1 * time.Minute // default of 1 minute
	}
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	maxBackoff := timeout
	if maxBackoff <= 0 {
		// indefinite timeout
		maxBackoff = 10 * time.Minute
	}

	resChan := make(chan waitResult)
	innerCtx, innerCancel := context.WithCancel(context.Background())
	defer innerCancel()
	go func() {
		backOff := expBackoffWithContext(innerCtx, 1*time.Second, maxBackoff)
		for {
			backOff.Wait()
			_, err := getDaemonState(innerCtx, DefaultDaemonTimeout)
			if errors.Is(err, context.Canceled) {
				resChan <- waitResult{err: err}
				return
			}
			if err == nil {
				resChan <- waitResult{}
				break
			}
		}
	}()

	var res waitResult
	select {
	case <-ctx.Done():
		innerCancel()
		res = <-resChan
	case res = <-resChan:
	}

	if res.err != nil {
		return res.err
	}
	return nil
}
