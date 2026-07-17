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
		// fbreceiver (Beats Filebeat) pulls in non-FIPS crypto through its Azure
		// Event Hubs input (AMQP/ADAL, pkcs12), Azure Blob Storage input (Azure
		// SDK, pkcs12), Active Directory entity analytics input (go-ldap, NTLM),
		// and GCS input (s2a-go/ALTS).
		"github.com/elastic/beats/v7/x-pack/filebeat/fbreceiver": {
			{Imported: "golang.org/x/crypto/pkcs12", Reason: "Azure inputs (Event Hubs, Blob Storage) load PKCS#12 client certificates"},
			{Imported: "github.com/Azure/go-ntlmssp", Reason: "Active Directory LDAP requires NTLM authentication"},
			{Imported: "golang.org/x/crypto/md4", Reason: "NTLM authentication requires MD4; no FIPS-approved substitute"},
			{Imported: "golang.org/x/crypto/chacha20poly1305", Reason: "GCS input pulls in s2a-go ALTS which uses ChaCha20-Poly1305"},
			{Imported: "golang.org/x/crypto/cryptobyte", Reason: "GCS input pulls in s2a-go ALTS which uses x/crypto ASN.1 utilities"},
			{Imported: "golang.org/x/crypto/hkdf", Reason: "GCS input pulls in s2a-go ALTS which uses HKDF for key derivation"},
		},

		// azureauthextension uses the Azure identity SDK for AAD authentication.
		"github.com/open-telemetry/opentelemetry-collector-contrib/extension/azureauthextension": {
			{Imported: "golang.org/x/crypto/pkcs12", Reason: "Azure identity SDK loads PKCS#12 client certificates for AAD auth"},
		},

		// opampextension uses s2a-go (ALTS) for secure OpAMP connections.
		"github.com/open-telemetry/opentelemetry-collector-contrib/extension/opampextension": {
			{Imported: "golang.org/x/crypto/chacha20poly1305", Reason: "ALTS S2A record layer uses ChaCha20-Poly1305 for session encryption"},
			{Imported: "golang.org/x/crypto/cryptobyte", Reason: "ALTS S2A record layer uses x/crypto ASN.1 utilities"},
			{Imported: "golang.org/x/crypto/hkdf", Reason: "ALTS S2A record layer uses HKDF for session key derivation"},
		},

		// apikeyauthextension uses x/crypto/pbkdf2 for APM API key derivation,
		// and pulls in go-tpm-keyfiles via confighttp -> configtls.
		"github.com/elastic/opentelemetry-collector-components/extension/apikeyauthextension": {
			{Imported: "golang.org/x/crypto/pbkdf2", Reason: "APM API key derivation uses PBKDF2; x/crypto not FIPS-certified"},
			{Imported: "golang.org/x/crypto/chacha20poly1305", Reason: "go-tpm-keyfiles (pulled via configtls) uses ChaCha20; no FIPS alternative"},
			{Imported: "golang.org/x/crypto/cryptobyte", Reason: "go-tpm-keyfiles (pulled via configtls) uses x/crypto ASN.1 utilities"},
			{Imported: "golang.org/x/crypto/cryptobyte/asn1", Reason: "go-tpm-keyfiles (pulled via configtls) uses x/crypto ASN.1 utilities"},
			{Imported: "golang.org/x/crypto/hkdf", Reason: "go-tpm-keyfiles (pulled via configtls) uses HKDF from x/crypto"},
		},

		// beatsauthextension uses elastic/gokrb5 (Elastic's Kerberos fork) for
		// Kerberos-based authentication in Beats components.
		"github.com/elastic/beats/v7/x-pack/otel/extension/beatsauthextension": {
			{Imported: "github.com/jcmturner/gofork/encoding/asn1", Reason: "Elastic gokrb5 fork depends on jcmturner gofork for ASN.1 encoding"},
			{Imported: "golang.org/x/crypto/md4", Reason: "Kerberos RC4-HMAC requires MD4; no FIPS-approved substitute"},
			{Imported: "github.com/jcmturner/aescts/v2", Reason: "Elastic gokrb5 fork depends on jcmturner aescts for AES-CBC-CTS"},
			{Imported: "github.com/jcmturner/gofork/x/crypto/pbkdf2", Reason: "Elastic gokrb5 fork depends on jcmturner gofork pbkdf2"},
			{Imported: "golang.org/x/crypto/pbkdf2", Reason: "Kerberos key derivation requires PBKDF2; x/crypto not FIPS-certified"},
		},

		// kafkametricsreceiver uses internal/kafka and franz-go with Kerberos
		// SASL (GSSAPI) and SCRAM SASL authentication.
		"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/kafkametricsreceiver": {
			{Imported: "github.com/jcmturner/gokrb5/v8/client", Reason: "Kafka Kerberos SASL (GSSAPI) requires gokrb5"},
			{Imported: "github.com/jcmturner/gokrb5/v8/config", Reason: "Kafka Kerberos SASL (GSSAPI) requires gokrb5"},
			{Imported: "github.com/jcmturner/gokrb5/v8/keytab", Reason: "Kafka Kerberos SASL (GSSAPI) requires gokrb5"},
			{Imported: "golang.org/x/crypto/pbkdf2", Reason: "Kafka SCRAM SASL key derivation uses PBKDF2; x/crypto not FIPS-certified"},
			{Imported: "github.com/jcmturner/gokrb5/v8/gssapi", Reason: "Kafka Kerberos SASL (GSSAPI) requires gokrb5"},
			{Imported: "github.com/jcmturner/gokrb5/v8/messages", Reason: "Kafka Kerberos SASL (GSSAPI) requires gokrb5"},
			{Imported: "github.com/jcmturner/gokrb5/v8/types", Reason: "Kafka Kerberos SASL (GSSAPI) requires gokrb5"},
		},

		// mongodbreceiver uses mongo-driver with youmark/pkcs8 for encrypted keys
		// and x/crypto/ocsp for certificate revocation.
		"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/mongodbreceiver": {
			{Imported: "github.com/youmark/pkcs8", Reason: "MongoDB TLS client auth with encrypted PKCS#8 keys requires youmark/pkcs8"},
			{Imported: "golang.org/x/crypto/ocsp", Reason: "MongoDB OCSP certificate revocation checking uses x/crypto/ocsp"},
		},

		// mysqlreceiver uses go-sql-driver/mysql which requires filippo.io/edwards25519
		// for the MySQL caching_sha2_password Ed25519 auth plugin.
		"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/mysqlreceiver": {
			{Imported: "filippo.io/edwards25519", Reason: "MySQL Ed25519 auth plugin requires edwards25519; not available in FIPS stdlib"},
		},

		// sqlserverreceiver uses go-mssqldb with Kerberos integrated auth and NTLM.
		"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/sqlserverreceiver": {
			{Imported: "github.com/jcmturner/gokrb5/v8/client", Reason: "SQL Server Kerberos integrated auth requires gokrb5"},
			{Imported: "github.com/jcmturner/gokrb5/v8/config", Reason: "SQL Server Kerberos integrated auth requires gokrb5"},
			{Imported: "github.com/jcmturner/gokrb5/v8/credentials", Reason: "SQL Server Kerberos integrated auth requires gokrb5"},
			{Imported: "github.com/jcmturner/gokrb5/v8/gssapi", Reason: "SQL Server Kerberos integrated auth requires gokrb5"},
			{Imported: "github.com/jcmturner/gokrb5/v8/keytab", Reason: "SQL Server Kerberos integrated auth requires gokrb5"},
			{Imported: "github.com/jcmturner/gokrb5/v8/spnego", Reason: "SQL Server Kerberos integrated auth requires gokrb5"},
			{Imported: "golang.org/x/crypto/md4", Reason: "SQL Server NTLM auth requires MD4; no FIPS-approved substitute"},
		},
	},
}

func TestFIPSCompliance(t *testing.T) {
	fipsscan.CheckModule(t, []string{"./..."}, skipBinaries, nil, knownViolations)
}
