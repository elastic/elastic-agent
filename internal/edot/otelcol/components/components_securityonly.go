// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build securityonly

package components

import "go.opentelemetry.io/collector/receiver"

// addFullBeatReceivers is intentionally a no-op for the security-only variant
// build: auditbeat and heartbeat receivers are not compiled in.
func addFullBeatReceivers(receivers []receiver.Factory) []receiver.Factory {
	return receivers
}
