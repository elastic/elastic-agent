// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package storage

import "io"

// NullStore this is only use to split the work into multiples PRs.
type NullStore struct{}

// Save takes the fleetConfig and persist it, will return an errors on failure.
func (m *NullStore) Save(_ io.Reader) error {
	return nil
}
