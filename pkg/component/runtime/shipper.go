package runtime

import "github.com/elastic/elastic-agent/internal/pkg/core/authority"

type shipperConn struct {
	addr  string
	ca    *authority.CertificateAuthority
	pairs map[string]*authority.Pair
}
