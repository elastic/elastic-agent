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

var knownViolations = map[string][]fipsscan.KnownViolation{
	"github.com/elastic/elastic-agent/internal/edot": {
		// Azure SDK and AMQP client use x/crypto/pkcs12 for PKCS#12 certificate loading.
		{Importer: "github.com/Azure/azure-amqp-common-go/v4/aad", Imported: "golang.org/x/crypto/pkcs12", Reason: "Azure AMQP AAD auth loads PKCS#12 certificates"},
		{Importer: "github.com/Azure/azure-sdk-for-go/sdk/azidentity", Imported: "golang.org/x/crypto/pkcs12", Reason: "Azure identity SDK loads PKCS#12 client certificates"},
		{Importer: "github.com/Azure/go-autorest/autorest/adal", Imported: "golang.org/x/crypto/pkcs12", Reason: "Azure ADAL loads PKCS#12 service principal certificates"},
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
		// apikeyauthextension uses x/crypto/pbkdf2 for APM API key derivation.
		{Importer: "github.com/elastic/opentelemetry-collector-components/extension/apikeyauthextension", Imported: "golang.org/x/crypto/pbkdf2", Reason: "APM API key derivation uses PBKDF2; x/crypto not FIPS-certified"},
		// go-tpm-keyfiles uses x/crypto for TPM key file parsing (ChaCha20, HKDF, ASN.1).
		{Importer: "github.com/foxboron/go-tpm-keyfiles", Imported: "golang.org/x/crypto/chacha20poly1305", Reason: "TPM key file parsing uses ChaCha20; no FIPS-certified alternative in go-tpm-keyfiles"},
		{Importer: "github.com/foxboron/go-tpm-keyfiles", Imported: "golang.org/x/crypto/cryptobyte", Reason: "TPM key file parsing uses x/crypto ASN.1 utilities"},
		{Importer: "github.com/foxboron/go-tpm-keyfiles", Imported: "golang.org/x/crypto/cryptobyte/asn1", Reason: "TPM key file parsing uses x/crypto ASN.1 utilities"},
		{Importer: "github.com/foxboron/go-tpm-keyfiles", Imported: "golang.org/x/crypto/hkdf", Reason: "TPM key file parsing uses HKDF from x/crypto"},
		// go-ldap uses go-ntlmssp for NTLM bind and x/crypto/md4 for NTLM hashing.
		{Importer: "github.com/go-ldap/ldap/v3", Imported: "github.com/Azure/go-ntlmssp", Reason: "Active Directory LDAP requires NTLM authentication support"},
		{Importer: "github.com/go-ldap/ldap/v3", Imported: "golang.org/x/crypto/md4", Reason: "NTLM authentication requires MD4; no FIPS-approved substitute"},
		// go-sql-driver/mysql uses Ed25519 for the MySQL caching_sha2_password auth plugin.
		{Importer: "github.com/go-sql-driver/mysql", Imported: "filippo.io/edwards25519", Reason: "MySQL Ed25519 auth plugin requires edwards25519; not available in FIPS stdlib"},
		// s2a-go (ALTS) uses x/crypto for ChaCha20-Poly1305 and HKDF in its record layer.
		{Importer: "github.com/google/s2a-go/internal/record/internal/aeadcrypter", Imported: "golang.org/x/crypto/chacha20poly1305", Reason: "ALTS S2A record layer uses ChaCha20-Poly1305 for session encryption"},
		{Importer: "github.com/google/s2a-go/internal/record/internal/halfconn", Imported: "golang.org/x/crypto/cryptobyte", Reason: "ALTS S2A record layer uses x/crypto ASN.1 utilities"},
		{Importer: "github.com/google/s2a-go/internal/record/internal/halfconn", Imported: "golang.org/x/crypto/hkdf", Reason: "ALTS S2A record layer uses HKDF for session key derivation"},
		// go-mssqldb uses jcmturner/gokrb5 for Kerberos auth and x/crypto/md4 for NTLM.
		{Importer: "github.com/microsoft/go-mssqldb/integratedauth/krb5", Imported: "github.com/jcmturner/gokrb5/v8/client", Reason: "SQL Server Kerberos integrated auth requires gokrb5"},
		{Importer: "github.com/microsoft/go-mssqldb/integratedauth/krb5", Imported: "github.com/jcmturner/gokrb5/v8/config", Reason: "SQL Server Kerberos integrated auth requires gokrb5"},
		{Importer: "github.com/microsoft/go-mssqldb/integratedauth/krb5", Imported: "github.com/jcmturner/gokrb5/v8/credentials", Reason: "SQL Server Kerberos integrated auth requires gokrb5"},
		{Importer: "github.com/microsoft/go-mssqldb/integratedauth/krb5", Imported: "github.com/jcmturner/gokrb5/v8/gssapi", Reason: "SQL Server Kerberos integrated auth requires gokrb5"},
		{Importer: "github.com/microsoft/go-mssqldb/integratedauth/krb5", Imported: "github.com/jcmturner/gokrb5/v8/keytab", Reason: "SQL Server Kerberos integrated auth requires gokrb5"},
		{Importer: "github.com/microsoft/go-mssqldb/integratedauth/krb5", Imported: "github.com/jcmturner/gokrb5/v8/spnego", Reason: "SQL Server Kerberos integrated auth requires gokrb5"},
		{Importer: "github.com/microsoft/go-mssqldb/integratedauth/ntlm", Imported: "golang.org/x/crypto/md4", Reason: "SQL Server NTLM auth requires MD4; no FIPS-approved substitute"},
		// mongo-driver uses youmark/pkcs8 for encrypted private key loading and x/crypto/ocsp for OCSP.
		{Importer: "go.mongodb.org/mongo-driver/v2/mongo/options", Imported: "github.com/youmark/pkcs8", Reason: "MongoDB TLS client auth with encrypted PKCS#8 keys requires youmark/pkcs8"},
		{Importer: "go.mongodb.org/mongo-driver/v2/x/mongo/driver/ocsp", Imported: "golang.org/x/crypto/ocsp", Reason: "MongoDB OCSP certificate revocation checking uses x/crypto/ocsp"},
		// otel-contrib Kafka internal package uses jcmturner/gokrb5 for Kerberos SASL (GSSAPI).
		{Importer: "github.com/open-telemetry/opentelemetry-collector-contrib/internal/kafka", Imported: "github.com/jcmturner/gokrb5/v8/client", Reason: "Kafka Kerberos SASL (GSSAPI) requires gokrb5"},
		{Importer: "github.com/open-telemetry/opentelemetry-collector-contrib/internal/kafka", Imported: "github.com/jcmturner/gokrb5/v8/config", Reason: "Kafka Kerberos SASL (GSSAPI) requires gokrb5"},
		{Importer: "github.com/open-telemetry/opentelemetry-collector-contrib/internal/kafka", Imported: "github.com/jcmturner/gokrb5/v8/keytab", Reason: "Kafka Kerberos SASL (GSSAPI) requires gokrb5"},
		// franz-go uses jcmturner/gokrb5 for Kerberos SASL and x/crypto for SCRAM/PBKDF2.
		{Importer: "github.com/twmb/franz-go/pkg/kadm", Imported: "golang.org/x/crypto/pbkdf2", Reason: "Kafka SCRAM SASL key derivation uses PBKDF2; x/crypto not FIPS-certified"},
		{Importer: "github.com/twmb/franz-go/pkg/sasl/kerberos", Imported: "github.com/jcmturner/gokrb5/v8/client", Reason: "Kafka Kerberos SASL (GSSAPI) requires gokrb5"},
		{Importer: "github.com/twmb/franz-go/pkg/sasl/kerberos", Imported: "github.com/jcmturner/gokrb5/v8/gssapi", Reason: "Kafka Kerberos SASL (GSSAPI) requires gokrb5"},
		{Importer: "github.com/twmb/franz-go/pkg/sasl/kerberos", Imported: "github.com/jcmturner/gokrb5/v8/messages", Reason: "Kafka Kerberos SASL (GSSAPI) requires gokrb5"},
		{Importer: "github.com/twmb/franz-go/pkg/sasl/kerberos", Imported: "github.com/jcmturner/gokrb5/v8/types", Reason: "Kafka Kerberos SASL (GSSAPI) requires gokrb5"},
		{Importer: "github.com/twmb/franz-go/pkg/sasl/scram", Imported: "golang.org/x/crypto/pbkdf2", Reason: "Kafka SCRAM SASL key derivation uses PBKDF2; x/crypto not FIPS-certified"},
	},
}

func TestFIPSCompliance(t *testing.T) {
	fipsscan.CheckModule(t, []string{"./..."}, skipBinaries, nil, knownViolations)
}
