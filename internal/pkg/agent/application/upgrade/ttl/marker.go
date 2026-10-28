// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package ttl

import "time"

// Kind says why an install is kept on disk until the TTL of its marker expires.
type Kind string

const (
	// KindRollback is an install that can be rolled back to.
	KindRollback Kind = "rollback"
	// KindDiagnostics is an install kept only so that the logs of a failed upgrade can be used to
	// troubleshoot it, it cannot be rolled back to.
	KindDiagnostics Kind = "diagnostics"
)

// TTLMarker marks an elastic-agent install kept on disk until ValidUntil, see Kind for the reasons.
type TTLMarker struct {
	Version    string    `json:"version" yaml:"version"`
	Hash       string    `json:"hash" yaml:"hash"`
	ValidUntil time.Time `json:"valid_until" yaml:"valid_until"`
	// Kind is why the install is kept. It is not written for rollbacks and an empty Kind means KindRollback,
	// so the markers written by agents that do not know the field stay valid.
	Kind Kind `json:"kind,omitempty" yaml:"kind,omitempty"`
}

// IsRollbackTarget returns true if the install can be rolled back to. A kind this version does not know is not
// a rollback target, it was written by a newer agent for another purpose.
func (m TTLMarker) IsRollbackTarget() bool {
	return m.Kind == "" || m.Kind == KindRollback
}
