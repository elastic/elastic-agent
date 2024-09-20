// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build !windows

package install

import (
	"time"
)

// isStopped waits until the service has stopped.  On non Windows
// systems this isn't necessary so just return.
func isStopped(timeout time.Duration, interval time.Duration, service string) error {
	return nil
}
