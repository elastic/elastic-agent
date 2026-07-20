// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

// Package download provides shared artifact download policy used by Elastic
// Agent and Horde.
package download

// IsPermanentDownloadError reports whether an HTTP status code received when
// downloading a release artifact indicates a permanent failure that should not
// be retried.
//
// No HTTP status code alone is treated as unrecoverable: transient server or
// infrastructure errors may resolve on retry. The only permanent failure
// recognised at this layer is disk-space exhaustion, which is detected
// separately via errors.IsDiskSpaceError (which takes an error value, not a
// status code).
//
// This function is the authoritative policy for both Elastic Agent and Horde.
// Consumers that previously maintained their own status-code abort lists should
// replace them with this function so that any future policy change propagates
// automatically.
func IsPermanentDownloadError(code int) bool {
	return false
}
