// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build requirefips

package components_test

import (
	"testing"

	"github.com/elastic/elastic-agent-libs/testing/fipsscan"
)

// knownViolations maps each EDOT component that transitively imports a
// non-FIPS crypto package to the reason it is a violation. Remove an entry
// once the component no longer reaches any forbidden package.
var knownViolations = map[string]string{
	"github.com/elastic/beats/v7/x-pack/filebeat/fbreceiver":                                  "transitively imports x/crypto (NTLM, PKCS#12/RC2) and go-ntlmssp (Active Directory LDAP)",
	"github.com/elastic/beats/v7/x-pack/otel/extension/beatsauthextension":                    "transitively imports x/crypto (Kerberos RC4-HMAC, pbkdf2)",
	"github.com/elastic/elastic-agent/internal/edot/receivers/verifierreceiver":               "transitively imports x/crypto (chacha20poly1305, hkdf, cryptobyte)",
	"github.com/elastic/opentelemetry-collector-components/extension/apikeyauthextension":     "transitively imports x/crypto/pbkdf2",
	"github.com/open-telemetry/opentelemetry-collector-contrib/extension/azureauthextension":  "transitively imports x/crypto/pkcs12 (PKCS#12/RC2 via Azure SDK)",
	"github.com/open-telemetry/opentelemetry-collector-contrib/extension/opampextension":      "transitively imports x/crypto (chacha20poly1305, hkdf, cryptobyte)",
	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/kafkametricsreceiver": "transitively imports x/crypto (Kerberos, pbkdf2)",
	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/mongodbreceiver":      "transitively imports x/crypto (pbkdf2, scrypt, ocsp) and youmark/pkcs8 (PKCS#8 key handling)",
	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/mysqlreceiver":        "transitively imports filippo.io/edwards25519 (MySQL Ed25519 auth plugin)",
	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/sqlserverreceiver":    "transitively imports x/crypto (Kerberos RC4-HMAC, NTLM)",
}

const (
	binaryPkg = "github.com/elastic/elastic-agent/internal/edot"
	rootPkg   = "github.com/elastic/elastic-agent/internal/edot/otelcol/components"
)

func TestFIPSFullyCompliant(t *testing.T) {
	fipsscan.CheckViolations(t, binaryPkg, rootPkg, nil, knownViolations)
}
