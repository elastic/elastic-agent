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
	// x/crypto/pbkdf2 delegates to crypto/hmac + the caller-supplied hash; when the hash is
	// crypto/sha512.New (as here), both primitives are FIPS-certified under GOFIPS140. The only
	// gap is that x/crypto/pbkdf2 itself is outside the certified module boundary. Prefer
	// crypto/pbkdf2 (Go 1.24, API-identical) to remove the ambiguity; one-line fix in Elastic repo.
	"github.com/elastic/opentelemetry-collector-components/extension/apikeyauthextension → golang.org/x/crypto/pbkdf2": "PBKDF2-HMAC-SHA-512; delegates to FIPS-certified crypto/hmac+sha512; swap to crypto/pbkdf2 (trivial)",
	// Kerberos uses MD4 for NTLMv1 (RC4-HMAC) — a legacy algorithm. If Kerberos
	// auth is configured in FIPS mode, only FIPS-approved enctypes should be used.
	"github.com/elastic/gokrb5/v8/crypto → golang.org/x/crypto/md4":           "Kerberos MD4 (NTLMv1/RC4-HMAC); disable non-FIPS enctypes in config",
	"github.com/elastic/gokrb5/v8/crypto/rfc4757 → golang.org/x/crypto/md4":   "Kerberos MD4 (RC4-HMAC legacy enctype)",
	// rfc8009 covers both aes*-hmac-sha1-96 (SHA-1, deprecated SP 800-131A rev2) and
	// aes*-hmac-sha256/384 (SHA-256/384, FIPS-approved). x/crypto/pbkdf2 delegates to
	// crypto/hmac; the SHA-1 path is the genuine concern here. Fix: gate sha1 enctypes
	// behind !requirefips in elastic/gokrb5 and replace x/crypto/pbkdf2 with crypto/pbkdf2.
	"github.com/elastic/gokrb5/v8/crypto/rfc8009 → golang.org/x/crypto/pbkdf2": "PBKDF2 via x/crypto; SHA-1 enctype paths deprecated SP 800-131A; fix in elastic/gokrb5",
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
	// NOTE: jcmturner/gokrb5 is abandoned (last commit 2023-05, 106 open issues); upstream PR
	// is not viable. Fix path: gate sqlserverreceiver behind !requirefips, or PR to
	// microsoft/go-mssqldb to replace this dependency.
	"github.com/jcmturner/gokrb5/v8/crypto → golang.org/x/crypto/md4":            "Kerberos MD4 (NTLMv1/RC4-HMAC); jcmturner/gokrb5 abandoned — gate sqlserverreceiver",
	"github.com/jcmturner/gokrb5/v8/crypto/rfc4757 → golang.org/x/crypto/md4":    "Kerberos MD4 (RC4-HMAC legacy enctype); jcmturner/gokrb5 abandoned",
	// SHA-1 paths deprecated; SHA-256/384 paths use FIPS-certified primitives via crypto/hmac.
	"github.com/jcmturner/gokrb5/v8/crypto/rfc8009 → golang.org/x/crypto/pbkdf2": "PBKDF2 via x/crypto; SHA-1 enctype paths deprecated SP 800-131A; jcmturner/gokrb5 abandoned",
	// go-mssqldb: NTLM for SQL Server integrated auth. Avoid in FIPS environments.
	"github.com/microsoft/go-mssqldb/integratedauth/ntlm → golang.org/x/crypto/md4": "MSSQL NTLM auth (MD4); use SQL auth instead in FIPS",
	// Prometheus exporter-toolkit: bcrypt for HTTP basic auth password hashing.
	// bcrypt (blowfish) is not FIPS-approved; affects prometheus receiver's HTTP server.
	"github.com/prometheus/exporter-toolkit/web → golang.org/x/crypto/bcrypt": "Prometheus HTTP basic auth (bcrypt/blowfish); not FIPS-approved",
	// franz-go SCRAM: passes crypto/sha256.New or crypto/sha512.New to x/crypto/pbkdf2, which
	// delegates to crypto/hmac. The PBKDF2-HMAC-SHA-256/512 computation goes through FIPS-certified
	// primitives. Only gap: x/crypto/pbkdf2 is outside the certified module boundary. One-line fix
	// available (crypto/pbkdf2, Go 1.24, API-identical); upstream PR to twmb/franz-go.
	"github.com/twmb/franz-go/pkg/kadm → golang.org/x/crypto/pbkdf2":       "PBKDF2-HMAC-SHA-256/512; FIPS-certified primitives; swap to crypto/pbkdf2 (upstream PR)",
	"github.com/twmb/franz-go/pkg/sasl/scram → golang.org/x/crypto/pbkdf2": "PBKDF2-HMAC-SHA-256/512; FIPS-certified primitives; swap to crypto/pbkdf2 (upstream PR)",
	// youmark/pkcs8: PBKDF2 with SHA-1 (default for older PKCS#8 format) or SHA-256.
	// SHA-1 use in PBKDF2 is deprecated under SP 800-131A rev2. The scrypt path is non-FIPS.
	"github.com/youmark/pkcs8 → golang.org/x/crypto/pbkdf2": "PKCS#8 PBKDF2; SHA-1 default path deprecated SP 800-131A; upstream fix needed",
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
