// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build boringcrypto

package release

import (
	"crypto/internal/boring/fipstls"
)

// FIPS returns true if FIPS boringcrypto is enabled.
func FIPS() bool {
	return fipstls.Required()
}
