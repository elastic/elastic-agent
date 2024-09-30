// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package common

// Logger is a simple logging interface used by each runner type.
type Logger interface {
	// Logf logs the message for this runner.
	Logf(format string, args ...any)
}
