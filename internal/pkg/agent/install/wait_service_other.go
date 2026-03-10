// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build !windows

package install

import (
	"time"

	"github.com/elastic/elastic-agent-libs/logp"
)

// isStopped waits until the service has stopped.  On non Windows
// systems this isn't necessary so just return.
func isStopped(_ *logp.Logger, _ time.Duration, _ time.Duration, _ string) error {
	return nil
}

// EnsureServiceRemoved waits until the service has been removed. On non
// Windows systems this isn't necessary so just return.
func EnsureServiceRemoved(timeout time.Duration, interval time.Duration, service string) error {
	return nil
}
