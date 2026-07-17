// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build requirefips

package components_test

import (
	"testing"

	"github.com/elastic/elastic-agent-libs/testing/fipsscan"
)

var knownViolations = map[string][]fipsscan.KnownViolation{
	"github.com/elastic/elastic-agent/internal/edot": {
		// Azure SDK and AMQP client use x/crypto/pkcs12 for certificate handling.
		{Importer: "github.com/Azure/azure-amqp-common-go/v4/aad", Imported: "golang.org/x/crypto/pkcs12"},
		{Importer: "github.com/Azure/azure-sdk-for-go/sdk/azidentity", Imported: "golang.org/x/crypto/pkcs12"},
		{Importer: "github.com/Azure/go-autorest/autorest/adal", Imported: "golang.org/x/crypto/pkcs12"},
		// elastic/gokrb5 is an Elastic fork of jcmturner/gokrb5 and pulls in jcmturner
		// support packages (gofork, aescts) and x/crypto routines (md4, pbkdf2, rc4).
		{Importer: "github.com/elastic/gokrb5/v8/asn1tools", Imported: "github.com/jcmturner/gofork/encoding/asn1"},
		{Importer: "github.com/elastic/gokrb5/v8/config", Imported: "github.com/jcmturner/gofork/encoding/asn1"},
		{Importer: "github.com/elastic/gokrb5/v8/credentials", Imported: "github.com/jcmturner/gofork/encoding/asn1"},
		{Importer: "github.com/elastic/gokrb5/v8/crypto", Imported: "golang.org/x/crypto/md4"},
		{Importer: "github.com/elastic/gokrb5/v8/crypto/rfc3962", Imported: "github.com/jcmturner/aescts/v2"},
		{Importer: "github.com/elastic/gokrb5/v8/crypto/rfc3962", Imported: "github.com/jcmturner/gofork/x/crypto/pbkdf2"},
		{Importer: "github.com/elastic/gokrb5/v8/crypto/rfc4757", Imported: "golang.org/x/crypto/md4"},
		{Importer: "github.com/elastic/gokrb5/v8/crypto/rfc8009", Imported: "github.com/jcmturner/aescts/v2"},
		{Importer: "github.com/elastic/gokrb5/v8/crypto/rfc8009", Imported: "golang.org/x/crypto/pbkdf2"},
		{Importer: "github.com/elastic/gokrb5/v8/gssapi", Imported: "github.com/jcmturner/gofork/encoding/asn1"},
		{Importer: "github.com/elastic/gokrb5/v8/kadmin", Imported: "github.com/jcmturner/gofork/encoding/asn1"},
		{Importer: "github.com/elastic/gokrb5/v8/messages", Imported: "github.com/jcmturner/gofork/encoding/asn1"},
		{Importer: "github.com/elastic/gokrb5/v8/spnego", Imported: "github.com/jcmturner/gofork/encoding/asn1"},
		{Importer: "github.com/elastic/gokrb5/v8/types", Imported: "github.com/jcmturner/gofork/encoding/asn1"},
		// apikeyauthextension uses x/crypto/pbkdf2 for API key derivation.
		{Importer: "github.com/elastic/opentelemetry-collector-components/extension/apikeyauthextension", Imported: "golang.org/x/crypto/pbkdf2"},
		// go-tpm-keyfiles uses x/crypto for TPM key file parsing (ChaCha20, HKDF, ASN.1).
		{Importer: "github.com/foxboron/go-tpm-keyfiles", Imported: "golang.org/x/crypto/chacha20poly1305"},
		{Importer: "github.com/foxboron/go-tpm-keyfiles", Imported: "golang.org/x/crypto/cryptobyte"},
		{Importer: "github.com/foxboron/go-tpm-keyfiles", Imported: "golang.org/x/crypto/cryptobyte/asn1"},
		{Importer: "github.com/foxboron/go-tpm-keyfiles", Imported: "golang.org/x/crypto/hkdf"},
		// go-ldap uses go-ntlmssp for NTLM bind (Active Directory) and x/crypto/md4 for NTLM hashing.
		{Importer: "github.com/go-ldap/ldap/v3", Imported: "github.com/Azure/go-ntlmssp"},
		{Importer: "github.com/go-ldap/ldap/v3", Imported: "golang.org/x/crypto/md4"},
		// go-sql-driver/mysql uses Ed25519 for the MySQL caching_sha2_password auth plugin.
		{Importer: "github.com/go-sql-driver/mysql", Imported: "filippo.io/edwards25519"},
		// s2a-go (ALTS) uses x/crypto for ChaCha20-Poly1305 and HKDF in its record layer.
		{Importer: "github.com/google/s2a-go/internal/record/internal/aeadcrypter", Imported: "golang.org/x/crypto/chacha20poly1305"},
		{Importer: "github.com/google/s2a-go/internal/record/internal/halfconn", Imported: "golang.org/x/crypto/cryptobyte"},
		{Importer: "github.com/google/s2a-go/internal/record/internal/halfconn", Imported: "golang.org/x/crypto/hkdf"},
		// go-mssqldb uses jcmturner/gokrb5 for Kerberos auth and x/crypto/md4 for NTLM.
		{Importer: "github.com/microsoft/go-mssqldb/integratedauth/krb5", Imported: "github.com/jcmturner/gokrb5/v8/client"},
		{Importer: "github.com/microsoft/go-mssqldb/integratedauth/krb5", Imported: "github.com/jcmturner/gokrb5/v8/config"},
		{Importer: "github.com/microsoft/go-mssqldb/integratedauth/krb5", Imported: "github.com/jcmturner/gokrb5/v8/credentials"},
		{Importer: "github.com/microsoft/go-mssqldb/integratedauth/krb5", Imported: "github.com/jcmturner/gokrb5/v8/gssapi"},
		{Importer: "github.com/microsoft/go-mssqldb/integratedauth/krb5", Imported: "github.com/jcmturner/gokrb5/v8/keytab"},
		{Importer: "github.com/microsoft/go-mssqldb/integratedauth/krb5", Imported: "github.com/jcmturner/gokrb5/v8/spnego"},
		{Importer: "github.com/microsoft/go-mssqldb/integratedauth/ntlm", Imported: "golang.org/x/crypto/md4"},
		// mongo-driver uses youmark/pkcs8 for encrypted private key parsing and x/crypto/ocsp for OCSP stapling.
		{Importer: "go.mongodb.org/mongo-driver/v2/mongo/options", Imported: "github.com/youmark/pkcs8"},
		{Importer: "go.mongodb.org/mongo-driver/v2/x/mongo/driver/ocsp", Imported: "golang.org/x/crypto/ocsp"},
		// otel-contrib Kafka receiver uses jcmturner/gokrb5 for Kerberos SASL.
		{Importer: "github.com/open-telemetry/opentelemetry-collector-contrib/internal/kafka", Imported: "github.com/jcmturner/gokrb5/v8/client"},
		{Importer: "github.com/open-telemetry/opentelemetry-collector-contrib/internal/kafka", Imported: "github.com/jcmturner/gokrb5/v8/config"},
		{Importer: "github.com/open-telemetry/opentelemetry-collector-contrib/internal/kafka", Imported: "github.com/jcmturner/gokrb5/v8/keytab"},
		// franz-go uses jcmturner/gokrb5 for Kerberos SASL and x/crypto for SCRAM and key derivation.
		{Importer: "github.com/twmb/franz-go/pkg/kadm", Imported: "golang.org/x/crypto/pbkdf2"},
		{Importer: "github.com/twmb/franz-go/pkg/sasl/kerberos", Imported: "github.com/jcmturner/gokrb5/v8/client"},
		{Importer: "github.com/twmb/franz-go/pkg/sasl/kerberos", Imported: "github.com/jcmturner/gokrb5/v8/gssapi"},
		{Importer: "github.com/twmb/franz-go/pkg/sasl/kerberos", Imported: "github.com/jcmturner/gokrb5/v8/messages"},
		{Importer: "github.com/twmb/franz-go/pkg/sasl/kerberos", Imported: "github.com/jcmturner/gokrb5/v8/types"},
		{Importer: "github.com/twmb/franz-go/pkg/sasl/scram", Imported: "golang.org/x/crypto/pbkdf2"},
	},
}

func TestFIPSCompliance(t *testing.T) {
	fipsscan.CheckModule(t, "github.com/elastic/elastic-agent/internal/edot", nil, knownViolations)
}
