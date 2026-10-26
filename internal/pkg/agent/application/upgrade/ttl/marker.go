// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package ttl

import "time"

// TTLMarker marks an elastic-agent install kept on disk until ValidUntil: an available rollback target,
// or an install retained for other reasons (see RetentionOnly)
type TTLMarker struct {
	Version    string    `json:"version" yaml:"version"`
	Hash       string    `json:"hash" yaml:"hash"`
	ValidUntil time.Time `json:"valid_until" yaml:"valid_until"`
	// RetentionOnly marks an install that is kept on disk until ValidUntil only for retention (for example the
	// logs of an upgrade that failed and was rolled back), not as a rollback target. It is protected from cleanup
	// like any unexpired entry. The zero value means a regular rollback target, so markers written by older
	// agents stay valid.
	RetentionOnly bool `json:"retention_only,omitempty" yaml:"retention_only,omitempty"`
}
