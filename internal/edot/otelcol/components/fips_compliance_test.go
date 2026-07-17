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
		// fbreceiver (Beats Filebeat) pulls in several non-FIPS libraries
		// through its Azure Event Hubs input, Active Directory entity analytics
		// input, and GCS input.
		"github.com/elastic/beats/v7/x-pack/filebeat/fbreceiver": {
			// Azure Event Hubs input uses AMQP AAD auth with PKCS#12 certificates.
			{Importer: "github.com/Azure/azure-amqp-common-go/v4/aad", Imported: "golang.org/x/crypto/pkcs12", Reason: "Azure AMQP AAD auth loads PKCS#12 certificates"},
			// Azure SDK is pulled in through the Azure Blob Storage input.
			{Importer: "github.com/Azure/azure-sdk-for-go/sdk/azidentity", Imported: "golang.org/x/crypto/pkcs12", Reason: "Azure identity SDK loads PKCS#12 client certificates"},
			// Azure Event Hubs input uses go-autorest ADAL with PKCS#12 certificates.
			{Importer: "github.com/Azure/go-autorest/autorest/adal", Imported: "golang.org/x/crypto/pkcs12", Reason: "Azure ADAL loads PKCS#12 service principal certificates"},
			// Active Directory entity analytics input uses LDAP with NTLM auth.
			{Importer: "github.com/go-ldap/ldap/v3", Imported: "github.com/Azure/go-ntlmssp", Reason: "Active Directory LDAP requires NTLM authentication support"},
			{Importer: "github.com/go-ldap/ldap/v3", Imported: "golang.org/x/crypto/md4", Reason: "NTLM authentication requires MD4; no FIPS-approved substitute"},
			// GCS input pulls in s2a-go (ALTS) through the GCS client library.
			{Importer: "github.com/google/s2a-go/internal/record/internal/aeadcrypter", Imported: "golang.org/x/crypto/chacha20poly1305", Reason: "ALTS S2A record layer uses ChaCha20-Poly1305 for session encryption"},
			{Importer: "github.com/google/s2a-go/internal/record/internal/halfconn", Imported: "golang.org/x/crypto/cryptobyte", Reason: "ALTS S2A record layer uses x/crypto ASN.1 utilities"},
			{Importer: "github.com/google/s2a-go/internal/record/internal/halfconn", Imported: "golang.org/x/crypto/hkdf", Reason: "ALTS S2A record layer uses HKDF for session key derivation"},
		},

		// azureauthextension uses the Azure identity SDK for AAD authentication.
		"github.com/open-telemetry/opentelemetry-collector-contrib/extension/azureauthextension": {
			{Importer: "github.com/Azure/azure-sdk-for-go/sdk/azidentity", Imported: "golang.org/x/crypto/pkcs12", Reason: "Azure identity SDK loads PKCS#12 client certificates"},
		},

		// opampextension uses s2a-go (ALTS) for secure OpAMP connections.
		"github.com/open-telemetry/opentelemetry-collector-contrib/extension/opampextension": {
			{Importer: "github.com/google/s2a-go/internal/record/internal/aeadcrypter", Imported: "golang.org/x/crypto/chacha20poly1305", Reason: "ALTS S2A record layer uses ChaCha20-Poly1305 for session encryption"},
			{Importer: "github.com/google/s2a-go/internal/record/internal/halfconn", Imported: "golang.org/x/crypto/cryptobyte", Reason: "ALTS S2A record layer uses x/crypto ASN.1 utilities"},
			{Importer: "github.com/google/s2a-go/internal/record/internal/halfconn", Imported: "golang.org/x/crypto/hkdf", Reason: "ALTS S2A record layer uses HKDF for session key derivation"},
		},

		// apikeyauthextension uses x/crypto/pbkdf2 for APM API key derivation,
		// and pulls in go-tpm-keyfiles via the configtls TLS infrastructure.
		"github.com/elastic/opentelemetry-collector-components/extension/apikeyauthextension": {
			{Importer: "github.com/elastic/opentelemetry-collector-components/extension/apikeyauthextension", Imported: "golang.org/x/crypto/pbkdf2", Reason: "APM API key derivation uses PBKDF2; x/crypto not FIPS-certified"},
			// go-tpm-keyfiles is pulled in via confighttp -> configtls for TLS with TPM-backed keys.
			{Importer: "github.com/foxboron/go-tpm-keyfiles", Imported: "golang.org/x/crypto/chacha20poly1305", Reason: "TPM key file parsing uses ChaCha20; no FIPS-certified alternative in go-tpm-keyfiles"},
			{Importer: "github.com/foxboron/go-tpm-keyfiles", Imported: "golang.org/x/crypto/cryptobyte", Reason: "TPM key file parsing uses x/crypto ASN.1 utilities"},
			{Importer: "github.com/foxboron/go-tpm-keyfiles", Imported: "golang.org/x/crypto/cryptobyte/asn1", Reason: "TPM key file parsing uses x/crypto ASN.1 utilities"},
			{Importer: "github.com/foxboron/go-tpm-keyfiles", Imported: "golang.org/x/crypto/hkdf", Reason: "TPM key file parsing uses HKDF from x/crypto"},
		},

		// beatsauthextension uses elastic/gokrb5 (Elastic's Kerberos fork) for
		// Kerberos-based authentication in Beats components.
		"github.com/elastic/beats/v7/x-pack/otel/extension/beatsauthextension": {
			// elastic/gokrb5 is an Elastic fork of jcmturner/gokrb5 and pulls in its
			// jcmturner support packages (gofork, aescts) and x/crypto (md4, pbkdf2).
			{Importer: "github.com/elastic/gokrb5/v8/asn1tools", Imported: "github.com/jcmturner/gofork/encoding/asn1", Reason: "Elastic gokrb5 fork depends on jcmturner gofork for ASN.1 encoding"},
			{Importer: "github.com/elastic/gokrb5/v8/config", Imported: "github.com/jcmturner/gofork/encoding/asn1", Reason: "Elastic gokrb5 fork depends on jcmturner gofork for ASN.1 encoding"},
			{Importer: "github.com/elastic/gokrb5/v8/credentials", Imported: "github.com/jcmturner/gofork/encoding/asn1", Reason: "Elastic gokrb5 fork depends on jcmturner gofork for ASN.1 encoding"},
			{Importer: "github.com/elastic/gokrb5/v8/crypto", Imported: "golang.org/x/crypto/md4", Reason: "Kerberos RC4-HMAC requires MD4; no FIPS-approved substitute"},
			{Importer: "github.com/elastic/gokrb5/v8/crypto/rfc3962", Imported: "github.com/jcmturner/aescts/v2", Reason: "Elastic gokrb5 fork depends on jcmturner aescts for AES-CBC-CTS"},
			{Importer: "github.com/elastic/gokrb5/v8/crypto/rfc3962", Imported: "github.com/jcmturner/gofork/x/crypto/pbkdf2", Reason: "Elastic gokrb5 fork depends on jcmturner gofork pbkdf2"},
			{Importer: "github.com/elastic/gokrb5/v8/crypto/rfc4757", Imported: "golang.org/x/crypto/md4", Reason: "Kerberos RC4-HMAC requires MD4; no FIPS-approved substitute"},
			{Importer: "github.com/elastic/gokrb5/v8/crypto/rfc8009", Imported: "github.com/jcmturner/aescts/v2", Reason: "Elastic gokrb5 fork depends on jcmturner aescts for AES-CBC-CTS"},
			{Importer: "github.com/elastic/gokrb5/v8/crypto/rfc8009", Imported: "golang.org/x/crypto/pbkdf2", Reason: "Kerberos key derivation requires PBKDF2; x/crypto not FIPS-certified"},
			{Importer: "github.com/elastic/gokrb5/v8/gssapi", Imported: "github.com/jcmturner/gofork/encoding/asn1", Reason: "Elastic gokrb5 fork depends on jcmturner gofork for ASN.1 encoding"},
			{Importer: "github.com/elastic/gokrb5/v8/kadmin", Imported: "github.com/jcmturner/gofork/encoding/asn1", Reason: "Elastic gokrb5 fork depends on jcmturner gofork for ASN.1 encoding"},
			{Importer: "github.com/elastic/gokrb5/v8/messages", Imported: "github.com/jcmturner/gofork/encoding/asn1", Reason: "Elastic gokrb5 fork depends on jcmturner gofork for ASN.1 encoding"},
			{Importer: "github.com/elastic/gokrb5/v8/spnego", Imported: "github.com/jcmturner/gofork/encoding/asn1", Reason: "Elastic gokrb5 fork depends on jcmturner gofork for ASN.1 encoding"},
			{Importer: "github.com/elastic/gokrb5/v8/types", Imported: "github.com/jcmturner/gofork/encoding/asn1", Reason: "Elastic gokrb5 fork depends on jcmturner gofork for ASN.1 encoding"},
		},

		// kafkametricsreceiver uses franz-go and internal/kafka with Kerberos
		// SASL (GSSAPI) and SCRAM SASL authentication.
		"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/kafkametricsreceiver": {
			// internal/kafka uses jcmturner/gokrb5 directly for Kerberos GSSAPI.
			{Importer: "github.com/open-telemetry/opentelemetry-collector-contrib/internal/kafka", Imported: "github.com/jcmturner/gokrb5/v8/client", Reason: "Kafka Kerberos SASL (GSSAPI) requires gokrb5"},
			{Importer: "github.com/open-telemetry/opentelemetry-collector-contrib/internal/kafka", Imported: "github.com/jcmturner/gokrb5/v8/config", Reason: "Kafka Kerberos SASL (GSSAPI) requires gokrb5"},
			{Importer: "github.com/open-telemetry/opentelemetry-collector-contrib/internal/kafka", Imported: "github.com/jcmturner/gokrb5/v8/keytab", Reason: "Kafka Kerberos SASL (GSSAPI) requires gokrb5"},
			// franz-go uses jcmturner/gokrb5 for Kerberos SASL and x/crypto for SCRAM.
			{Importer: "github.com/twmb/franz-go/pkg/kadm", Imported: "golang.org/x/crypto/pbkdf2", Reason: "Kafka SCRAM SASL key derivation uses PBKDF2; x/crypto not FIPS-certified"},
			{Importer: "github.com/twmb/franz-go/pkg/sasl/kerberos", Imported: "github.com/jcmturner/gokrb5/v8/client", Reason: "Kafka Kerberos SASL (GSSAPI) requires gokrb5"},
			{Importer: "github.com/twmb/franz-go/pkg/sasl/kerberos", Imported: "github.com/jcmturner/gokrb5/v8/gssapi", Reason: "Kafka Kerberos SASL (GSSAPI) requires gokrb5"},
			{Importer: "github.com/twmb/franz-go/pkg/sasl/kerberos", Imported: "github.com/jcmturner/gokrb5/v8/messages", Reason: "Kafka Kerberos SASL (GSSAPI) requires gokrb5"},
			{Importer: "github.com/twmb/franz-go/pkg/sasl/kerberos", Imported: "github.com/jcmturner/gokrb5/v8/types", Reason: "Kafka Kerberos SASL (GSSAPI) requires gokrb5"},
			{Importer: "github.com/twmb/franz-go/pkg/sasl/scram", Imported: "golang.org/x/crypto/pbkdf2", Reason: "Kafka SCRAM SASL key derivation uses PBKDF2; x/crypto not FIPS-certified"},
		},

		// mongodbreceiver uses mongo-driver which requires youmark/pkcs8 for
		// encrypted PKCS#8 keys and x/crypto/ocsp for certificate revocation.
		"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/mongodbreceiver": {
			{Importer: "go.mongodb.org/mongo-driver/v2/mongo/options", Imported: "github.com/youmark/pkcs8", Reason: "MongoDB TLS client auth with encrypted PKCS#8 keys requires youmark/pkcs8"},
			{Importer: "go.mongodb.org/mongo-driver/v2/x/mongo/driver/ocsp", Imported: "golang.org/x/crypto/ocsp", Reason: "MongoDB OCSP certificate revocation checking uses x/crypto/ocsp"},
		},

		// mysqlreceiver uses go-sql-driver/mysql which requires filippo.io/edwards25519
		// for the MySQL caching_sha2_password Ed25519 auth plugin.
		"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/mysqlreceiver": {
			{Importer: "github.com/go-sql-driver/mysql", Imported: "filippo.io/edwards25519", Reason: "MySQL Ed25519 auth plugin requires edwards25519; not available in FIPS stdlib"},
		},

		// sqlserverreceiver uses go-mssqldb with Kerberos integrated auth and NTLM.
		"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/sqlserverreceiver": {
			{Importer: "github.com/microsoft/go-mssqldb/integratedauth/krb5", Imported: "github.com/jcmturner/gokrb5/v8/client", Reason: "SQL Server Kerberos integrated auth requires gokrb5"},
			{Importer: "github.com/microsoft/go-mssqldb/integratedauth/krb5", Imported: "github.com/jcmturner/gokrb5/v8/config", Reason: "SQL Server Kerberos integrated auth requires gokrb5"},
			{Importer: "github.com/microsoft/go-mssqldb/integratedauth/krb5", Imported: "github.com/jcmturner/gokrb5/v8/credentials", Reason: "SQL Server Kerberos integrated auth requires gokrb5"},
			{Importer: "github.com/microsoft/go-mssqldb/integratedauth/krb5", Imported: "github.com/jcmturner/gokrb5/v8/gssapi", Reason: "SQL Server Kerberos integrated auth requires gokrb5"},
			{Importer: "github.com/microsoft/go-mssqldb/integratedauth/krb5", Imported: "github.com/jcmturner/gokrb5/v8/keytab", Reason: "SQL Server Kerberos integrated auth requires gokrb5"},
			{Importer: "github.com/microsoft/go-mssqldb/integratedauth/krb5", Imported: "github.com/jcmturner/gokrb5/v8/spnego", Reason: "SQL Server Kerberos integrated auth requires gokrb5"},
			{Importer: "github.com/microsoft/go-mssqldb/integratedauth/ntlm", Imported: "golang.org/x/crypto/md4", Reason: "SQL Server NTLM auth requires MD4; no FIPS-approved substitute"},
		},
	},
}

func TestFIPSCompliance(t *testing.T) {
	fipsscan.CheckModule(t, []string{"./..."}, skipBinaries, nil, knownViolations)
}
