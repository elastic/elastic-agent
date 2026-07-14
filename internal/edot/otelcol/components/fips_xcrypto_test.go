// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build requirefips

package components_test

// TestFIPSNoNewXCryptoImports audits the FIPS component dependency tree for
// direct imports of golang.org/x/crypto, which is NOT covered by Go's FIPS
// 140-3 certified module (GOFIPS140). Only crypto/* standard library packages
// are FIPS-certified; x/crypto has its own implementations that bypass the
// FIPS boundary.
//
// The test maintains a known allowlist of existing x/crypto users. Adding a
// new component that brings in an x/crypto import that is not in the allowlist
// will fail this test, requiring a conscious review decision:
//   - If the use is acceptable (e.g. a non-security code path, or the algorithm
//     is allowed under FIPS with a waiver), add it to knownXCryptoImports with
//     a comment explaining why.
//   - If it is not acceptable, the component must stay in components_nofips.go.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"testing"
)

// knownXCryptoImports lists importer→import pairs already present when this
// test was introduced. Each entry should have a comment explaining the risk.
//
// Key format: "importer → golang.org/x/crypto/subpkg"
var knownXCryptoImports = map[string]string{
	// Azure SDK: pkcs12 used for certificate handling, not data encryption.
	"github.com/Azure/azure-amqp-common-go/v4/aad → golang.org/x/crypto/pkcs12":          "Azure cert handling",
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity → golang.org/x/crypto/pkcs12":      "Azure cert handling",
	"github.com/Azure/go-autorest/autorest/adal → golang.org/x/crypto/pkcs12":             "Azure cert handling",
	"github.com/elastic/opentelemetry-collector-components/extension/apikeyauthextension → golang.org/x/crypto/pbkdf2": "PBKDF2 key derivation for API key storage; needs upstream fix to use crypto/pbkdf2",
	// Kerberos uses MD4 for NTLMv1 (RC4-HMAC) — a legacy algorithm. If Kerberos
	// auth is configured in FIPS mode, only FIPS-approved enctypes should be used.
	"github.com/elastic/gokrb5/v8/crypto → golang.org/x/crypto/md4":           "Kerberos MD4 (NTLMv1/RC4-HMAC); disable non-FIPS enctypes in config",
	"github.com/elastic/gokrb5/v8/crypto/rfc4757 → golang.org/x/crypto/md4":   "Kerberos MD4 (RC4-HMAC legacy enctype)",
	"github.com/elastic/gokrb5/v8/crypto/rfc8009 → golang.org/x/crypto/pbkdf2": "Kerberos PBKDF2 (AES-128/256 enctype); needs upstream fix",
	// go-tpm-keyfiles: TPM key file format parsing (platform key management, not data crypto).
	"github.com/foxboron/go-tpm-keyfiles → golang.org/x/crypto/chacha20poly1305": "TPM key file format; ChaCha20-Poly1305 is not FIPS-approved",
	"github.com/foxboron/go-tpm-keyfiles → golang.org/x/crypto/cryptobyte":       "TPM key file ASN.1 parsing",
	"github.com/foxboron/go-tpm-keyfiles → golang.org/x/crypto/cryptobyte/asn1":  "TPM key file ASN.1 parsing",
	"github.com/foxboron/go-tpm-keyfiles → golang.org/x/crypto/hkdf":             "TPM key derivation; HKDF not FIPS-certified via x/crypto",
	// LDAP: MD4 used for NTLM challenge-response. Avoid NTLM bind in FIPS environments.
	"github.com/go-ldap/ldap/v3 → golang.org/x/crypto/md4": "LDAP NTLM auth (MD4); use Kerberos or simple bind instead",
	// Google S2A (Session to Application layer security) — used by Google Cloud client libs.
	"github.com/google/s2a-go/internal/record/internal/aeadcrypter → golang.org/x/crypto/chacha20poly1305": "Google S2A ChaCha20-Poly1305; not FIPS-approved",
	"github.com/google/s2a-go/internal/record/internal/halfconn → golang.org/x/crypto/cryptobyte":          "Google S2A TLS record parsing",
	"github.com/google/s2a-go/internal/record/internal/halfconn → golang.org/x/crypto/hkdf":               "Google S2A key derivation",
	// jcmturner/gokrb5: same Kerberos concerns as elastic/gokrb5 above.
	"github.com/jcmturner/gokrb5/v8/crypto → golang.org/x/crypto/md4":            "Kerberos MD4 (NTLMv1/RC4-HMAC)",
	"github.com/jcmturner/gokrb5/v8/crypto/rfc4757 → golang.org/x/crypto/md4":    "Kerberos MD4 (RC4-HMAC legacy enctype)",
	"github.com/jcmturner/gokrb5/v8/crypto/rfc8009 → golang.org/x/crypto/pbkdf2": "Kerberos PBKDF2; needs upstream fix",
	// go-mssqldb: NTLM for SQL Server integrated auth. Avoid in FIPS environments.
	"github.com/microsoft/go-mssqldb/integratedauth/ntlm → golang.org/x/crypto/md4": "MSSQL NTLM auth (MD4); use SQL auth instead in FIPS",
	// Prometheus exporter-toolkit: bcrypt for HTTP basic auth password hashing.
	// bcrypt (blowfish) is not FIPS-approved; affects prometheus receiver's HTTP server.
	"github.com/prometheus/exporter-toolkit/web → golang.org/x/crypto/bcrypt": "Prometheus HTTP basic auth (bcrypt/blowfish); not FIPS-approved",
	// franz-go: SCRAM auth for Kafka uses PBKDF2 via x/crypto. This is the kafka
	// receiver/exporter's underlying client. SCRAM-SHA-256/512 PBKDF2 should ideally
	// use crypto/pbkdf2 (Go 1.24+); needs upstream fix in franz-go.
	"github.com/twmb/franz-go/pkg/kadm → golang.org/x/crypto/pbkdf2":       "Kafka SCRAM PBKDF2; needs upstream fix in franz-go",
	"github.com/twmb/franz-go/pkg/sasl/scram → golang.org/x/crypto/pbkdf2": "Kafka SCRAM PBKDF2; needs upstream fix in franz-go",
	// youmark/pkcs8: PKCS#8 key parsing (pbkdf2+scrypt for encrypted keys).
	"github.com/youmark/pkcs8 → golang.org/x/crypto/pbkdf2": "PKCS#8 encrypted key parsing; needs upstream fix",
	"github.com/youmark/pkcs8 → golang.org/x/crypto/scrypt":  "PKCS#8 scrypt key derivation; not FIPS-approved",
	// MongoDB driver: OCSP (certificate status checking) — uses x/crypto/ocsp for TLS.
	"go.mongodb.org/mongo-driver/v2/x/mongo/driver/ocsp → golang.org/x/crypto/ocsp": "MongoDB OCSP cert validation; non-data-path TLS",
	// x/crypto internal self-references (not third-party users, just the module itself).
	"golang.org/x/crypto/bcrypt → golang.org/x/crypto/blowfish":                  "x/crypto internal",
	"golang.org/x/crypto/chacha20 → golang.org/x/crypto/internal/alias":           "x/crypto internal",
	"golang.org/x/crypto/chacha20poly1305 → golang.org/x/crypto/chacha20":         "x/crypto internal",
	"golang.org/x/crypto/chacha20poly1305 → golang.org/x/crypto/internal/alias":   "x/crypto internal",
	"golang.org/x/crypto/chacha20poly1305 → golang.org/x/crypto/internal/poly1305": "x/crypto internal",
	"golang.org/x/crypto/cryptobyte → golang.org/x/crypto/cryptobyte/asn1":        "x/crypto internal",
	"golang.org/x/crypto/pkcs12 → golang.org/x/crypto/pkcs12/internal/rc2":        "x/crypto internal",
	"golang.org/x/crypto/scrypt → golang.org/x/crypto/pbkdf2":                     "x/crypto internal",
}

func TestFIPSNoNewXCryptoImports(t *testing.T) {
	type goPackage struct {
		ImportPath string   `json:"ImportPath"`
		Imports    []string `json:"Imports"`
		Standard   bool     `json:"Standard"`
	}

	cmd := exec.Command("go", "list", "-json", "-deps", "-tags", "requirefips", ".")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}

	dec := json.NewDecoder(bytes.NewReader(out))
	var newViolations []string

	for {
		var p goPackage
		if err := dec.Decode(&p); err == io.EOF {
			break
		} else if err != nil {
			t.Fatalf("decode: %v", err)
		}
		if p.Standard {
			continue
		}
		for _, imp := range p.Imports {
			if !strings.HasPrefix(imp, "golang.org/x/crypto") {
				continue
			}
			key := fmt.Sprintf("%s → %s", p.ImportPath, imp)
			if _, known := knownXCryptoImports[key]; !known {
				newViolations = append(newViolations, key)
			}
		}
	}

	if len(newViolations) > 0 {
		t.Errorf("new golang.org/x/crypto imports found in FIPS build (not FIPS-certified).\n"+
			"Add to knownXCryptoImports with a justification comment if acceptable,\n"+
			"or keep the component in components_nofips.go:\n  %s",
			strings.Join(newViolations, "\n  "))
	}
}
