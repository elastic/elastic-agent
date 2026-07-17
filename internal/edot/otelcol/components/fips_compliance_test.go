// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build requirefips

package components_test

import (
	"testing"

	"github.com/elastic/elastic-agent-libs/testing/fipsscan"
)

// skipBinaries lists non-shipped binaries in this module excluded from the scan.
var skipBinaries = []string{
	"github.com/elastic/elastic-agent/internal/edot/testing",
}

var knownViolations = map[string]map[string][]fipsscan.KnownViolation{
	"github.com/elastic/elastic-agent/internal/edot": {
		// fbreceiver (Beats Filebeat): Azure Event Hubs/Blob Storage (pkcs12),
		// Active Directory LDAP (NTLM/md4), GCS input (s2a-go/ALTS).
		"github.com/elastic/beats/v7/x-pack/filebeat/fbreceiver": {
			{Imported: "golang.org/x/crypto", Reason: "Azure inputs (pkcs12), NTLM (md4), GCS s2a-go ALTS (chacha20, hkdf, cryptobyte)"},
			{Imported: "github.com/Azure/go-ntlmssp", Reason: "Active Directory LDAP requires NTLM authentication"},
		},

		// azureauthextension: Azure identity SDK for AAD authentication.
		"github.com/open-telemetry/opentelemetry-collector-contrib/extension/azureauthextension": {
			{Imported: "golang.org/x/crypto", Reason: "Azure identity SDK loads PKCS#12 client certificates for AAD auth"},
		},

		// opampextension: s2a-go (ALTS) for secure OpAMP connections.
		"github.com/open-telemetry/opentelemetry-collector-contrib/extension/opampextension": {
			{Imported: "golang.org/x/crypto", Reason: "ALTS S2A record layer uses ChaCha20-Poly1305, HKDF, cryptobyte"},
		},

		// apikeyauthextension: PBKDF2 for APM API key derivation;
		// go-tpm-keyfiles pulled in via confighttp -> configtls.
		"github.com/elastic/opentelemetry-collector-components/extension/apikeyauthextension": {
			{Imported: "golang.org/x/crypto", Reason: "PBKDF2 for API key derivation; ChaCha20/HKDF/cryptobyte via go-tpm-keyfiles (configtls)"},
		},

		// beatsauthextension: elastic/gokrb5 fork for Kerberos auth.
		"github.com/elastic/beats/v7/x-pack/otel/extension/beatsauthextension": {
			{Imported: "github.com/jcmturner", Reason: "Elastic gokrb5 fork depends on jcmturner gofork (ASN.1, pbkdf2) and aescts (AES-CBC-CTS)"},
			{Imported: "golang.org/x/crypto", Reason: "Kerberos RC4-HMAC (md4) and key derivation (pbkdf2); x/crypto not FIPS-certified"},
		},

		// kafkametricsreceiver: Kerberos SASL (GSSAPI) and SCRAM SASL.
		"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/kafkametricsreceiver": {
			{Imported: "github.com/jcmturner/gokrb5/v8", Reason: "Kafka Kerberos SASL (GSSAPI) requires gokrb5"},
			{Imported: "golang.org/x/crypto", Reason: "Kafka SCRAM SASL key derivation uses PBKDF2; x/crypto not FIPS-certified"},
		},

		// mongodbreceiver: encrypted PKCS#8 keys and OCSP revocation.
		"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/mongodbreceiver": {
			{Imported: "github.com/youmark/pkcs8", Reason: "MongoDB TLS client auth with encrypted PKCS#8 keys requires youmark/pkcs8"},
			{Imported: "golang.org/x/crypto", Reason: "MongoDB OCSP certificate revocation checking uses x/crypto/ocsp"},
		},

		// mysqlreceiver: Ed25519 auth plugin.
		"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/mysqlreceiver": {
			{Imported: "filippo.io/edwards25519", Reason: "MySQL Ed25519 auth plugin requires edwards25519; not available in FIPS stdlib"},
		},

		// sqlserverreceiver: Kerberos integrated auth and NTLM.
		"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/sqlserverreceiver": {
			{Imported: "github.com/jcmturner/gokrb5/v8", Reason: "SQL Server Kerberos integrated auth requires gokrb5"},
			{Imported: "golang.org/x/crypto", Reason: "SQL Server NTLM auth requires MD4; no FIPS-approved substitute"},
		},
	},
}

func TestFIPSCompliance(t *testing.T) {
	fipsscan.CheckModule(t, []string{"./..."}, skipBinaries, nil, knownViolations)
}
