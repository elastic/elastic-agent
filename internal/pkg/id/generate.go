// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package id

import (
	"crypto/rand"
	"time"

	"github.com/oklog/ulid/v2"
)

// ID represents a unique ID.
type ID = ulid.ULID

// Generate returns and ID or an error if we cannot generate an ID.
func Generate() (ID, error) {
	t := time.Now()
	entropy := ulid.Monotonic(rand.Reader, 0)
	return ulid.New(ulid.Timestamp(t), entropy)
}
