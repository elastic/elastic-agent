// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package runtime

import "github.com/elastic/elastic-agent/internal/pkg/core/authority"

type shipperConn struct {
	addr  string
	ca    *authority.CertificateAuthority
	pairs map[string]*authority.Pair
}
