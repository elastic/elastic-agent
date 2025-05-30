// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package manager

import "context"

// reportErr reports an error to the error channel, after draining it.
func reportErr(ctx context.Context, errCh chan error, err error) {
	select {
	case <-ctx.Done():
		// context is already done
		return
	case <-errCh:
	// drain the error channel first
	default:
	}
	select {
	case errCh <- err:
	case <-ctx.Done():
	}
}
