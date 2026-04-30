// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package backoff

import (
	"time"

	publicbackoff "github.com/elastic/elastic-agent/pkg/backoff"
)

type ExpBackoff = publicbackoff.ExpBackoff

func NewExpBackoff(done <-chan struct{}, init, max time.Duration) Backoff {
	return publicbackoff.NewExpBackoff(done, init, max)
}
