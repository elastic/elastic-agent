// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package ttl

// ReadOnlySource is the read-only view of the TTL rollback registry.
type ReadOnlySource interface {
	// GetAll reads all on-disk TTL markers and returns three values:
	//   - markers (map[string]TTLMarker): successfully parsed entries, keyed by versioned home path.
	//   - malformed (map[string]error): per-entry parse errors for entries that could not be read
	//     or parsed, also keyed by versioned home path.
	//   - err: non-nil only on structural failures (e.g. glob error) where no scan could be
	//     performed; in that case both maps are nil.
	GetAll() (map[string]TTLMarker, map[string]error, error)
}

// Source is the persistence layer for TTL-based rollback markers.
type Source interface {
	ReadOnlySource
	// Set reconciles the on-disk markers with the desired state: entries absent
	// from m are removed, entries present in m are written (created or overwritten).
	Set(m map[string]TTLMarker) error
	// Remove deletes the TTL marker for the given versioned home path.
	// A missing marker is not an error.
	Remove(versionedHome string) error
}
