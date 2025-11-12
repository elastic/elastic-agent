// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package ttl

import "time"

// TTLMarker marks an elastic-agent install available for rollback
type TTLMarker struct {
	Version    string    `json:"version" yaml:"version"`
	Hash       string    `json:"hash" yaml:"hash"`
	ValidUntil time.Time `json:"valid_until" yaml:"valid_until"`
}
