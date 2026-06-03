// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package fleetapi

import "time"

// Backoff constants for Fleet Server client operations. Exported so external
// consumers (e.g. Horde) can use the same values and avoid drift.

// EnrollBackoffInit is the initial backoff duration for enrollment retries.
const EnrollBackoffInit = 5 * time.Second

// EnrollBackoffMax is the maximum backoff duration for enrollment retries.
const EnrollBackoffMax = 10 * time.Minute

// AckBackoffInit is the initial backoff duration for action-ack retries.
const AckBackoffInit = 1 * time.Minute

// AckBackoffMax is the maximum backoff duration for action-ack retries.
const AckBackoffMax = 5 * time.Minute
