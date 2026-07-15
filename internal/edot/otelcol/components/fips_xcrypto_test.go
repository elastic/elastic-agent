// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build requirefips

package components_test

// Tests in this file audit the FIPS build for golang.org/x/crypto imports.
// golang.org/x/crypto is NOT covered by Go's FIPS 140-3 certified module
// (GOFIPS140); only crypto/* standard library packages are certified.
//
// TestFIPSFullyCompliant reports all violations with their full dependency
// chain and fails on any violation not listed in knownViolations. Remove
// entries from knownViolations as fixes land. Once the map is empty the test
// becomes a strict no-violations gate.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"testing"
)

// knownViolations lists all current x/crypto imports in the FIPS build.
// Key: "importer → x/crypto/subpkg". Remove entries as violations are fixed.
var knownViolations = map[string]string{
	// --- bcrypt (Blowfish) — not FIPS-approved ---
	// Fix: keep prometheusreceiver in !requirefips until exporter-toolkit adds a !requirefips guard.
	// Upstream has no appetite for a requirefips tag; FIPS deployments use mTLS not bcrypt passwords.
	"github.com/prometheus/exporter-toolkit/web → golang.org/x/crypto/bcrypt": "bcrypt/blowfish not FIPS-approved; move prometheusreceiver to !requirefips",

	// --- MD4 — not FIPS-approved ---
	// Used by Kerberos RC4-HMAC (NTLMv1) and LDAP/MSSQL NTLM.
	// elastic/gokrb5: gate rc4-hmac.go + rfc4757 behind //go:build !requirefips.
	"github.com/elastic/gokrb5/v8/crypto → golang.org/x/crypto/md4":               "Kerberos RC4-HMAC (MD4); gate rc4-hmac.go + rfc4757 behind !requirefips in elastic/gokrb5",
	"github.com/elastic/gokrb5/v8/crypto/rfc4757 → golang.org/x/crypto/md4":        "Kerberos RC4-HMAC rfc4757 (MD4); gate in elastic/gokrb5",
	// go-ldap/ldap: upstream PR using crypto/fips140.Enabled().
	"github.com/go-ldap/ldap/v3 → golang.org/x/crypto/md4": "LDAP NTLM (MD4); upstream PR to go-ldap/ldap using fips140.Enabled()",
	// jcmturner/gokrb5 is abandoned (last commit 2023-05). Gate sqlserverreceiver behind !requirefips.
	"github.com/jcmturner/gokrb5/v8/crypto → golang.org/x/crypto/md4":               "Kerberos RC4-HMAC (MD4); jcmturner/gokrb5 abandoned — gate sqlserverreceiver behind !requirefips",
	"github.com/jcmturner/gokrb5/v8/crypto/rfc4757 → golang.org/x/crypto/md4":        "Kerberos rfc4757 (MD4); jcmturner/gokrb5 abandoned",
	"github.com/microsoft/go-mssqldb/integratedauth/ntlm → golang.org/x/crypto/md4": "MSSQL NTLM (MD4); upstream PR to go-mssqldb using fips140.Enabled()",

	// --- scrypt — not FIPS-approved ---
	// Fix: upstream PR to youmark/pkcs8 using fips140.Enabled() + PBKDF2+AES alternative.
	"github.com/youmark/pkcs8 → golang.org/x/crypto/scrypt": "PKCS#8 scrypt not FIPS-approved; upstream PR to youmark/pkcs8",

	// --- pkcs12 (RC2/DES) — not FIPS-approved ---
	// Azure SDK pulls in pkcs12 for certificate auth. Gate Azure-dependent components.
	"github.com/Azure/azure-amqp-common-go/v4/aad → golang.org/x/crypto/pkcs12":      "PKCS#12/RC2 via Azure SDK; gate fbreceiver Azure inputs behind !requirefips",
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity → golang.org/x/crypto/pkcs12":  "PKCS#12/RC2 via Azure SDK; gate azuremonitorreceiver behind !requirefips",
	"github.com/Azure/go-autorest/autorest/adal → golang.org/x/crypto/pkcs12":         "PKCS#12/RC2 via Azure SDK; gate fbreceiver Azure inputs behind !requirefips",

	// --- pbkdf2 — x/crypto/pbkdf2 delegates to crypto/hmac internally ---
	// When called with SHA-256/512 from crypto/*, the actual HMAC computation goes through
	// FIPS-certified crypto/hmac. The only gap is that x/crypto/pbkdf2 sits outside the
	// certified module boundary. SHA-1 paths (aes*-cts-hmac-sha1-96 enctypes) are additionally
	// deprecated under SP 800-131A rev2.
	// Fix for Elastic-owned: swap x/crypto/pbkdf2 → crypto/pbkdf2 (Go 1.24, API-identical).
	"github.com/elastic/opentelemetry-collector-components/extension/apikeyauthextension → golang.org/x/crypto/pbkdf2": "PBKDF2-HMAC-SHA-512; swap to crypto/pbkdf2 in elastic/opentelemetry-collector-components",
	"github.com/elastic/gokrb5/v8/crypto/rfc8009 → golang.org/x/crypto/pbkdf2":                                         "PBKDF2 (includes SHA-1 enctype paths, deprecated SP 800-131A rev2); fix in elastic/gokrb5",
	"github.com/jcmturner/gokrb5/v8/crypto/rfc8009 → golang.org/x/crypto/pbkdf2":                                       "PBKDF2 (SHA-1 paths deprecated); jcmturner/gokrb5 abandoned — gate sqlserverreceiver",
	"github.com/twmb/franz-go/pkg/kadm → golang.org/x/crypto/pbkdf2":                                                    "PBKDF2-HMAC-SHA-256/512; upstream PR to twmb/franz-go to swap to crypto/pbkdf2",
	"github.com/twmb/franz-go/pkg/sasl/scram → golang.org/x/crypto/pbkdf2":                                              "PBKDF2-HMAC-SHA-256/512; upstream PR to twmb/franz-go to swap to crypto/pbkdf2",
	"github.com/youmark/pkcs8 → golang.org/x/crypto/pbkdf2":                                                              "PKCS#8 PBKDF2 (SHA-1 default path deprecated); upstream PR to youmark/pkcs8",

	// --- chacha20poly1305 / hkdf / cryptobyte — TLS infrastructure ---
	// Present via go-tpm-keyfiles (TPM key format) and Google S2A (GCP TLS).
	// ChaCha20-Poly1305 and HKDF are not FIPS-approved via x/crypto.
	"github.com/foxboron/go-tpm-keyfiles → golang.org/x/crypto/chacha20poly1305":                      "TPM key file format (ChaCha20-Poly1305 not FIPS-approved)",
	"github.com/foxboron/go-tpm-keyfiles → golang.org/x/crypto/cryptobyte":                            "TPM key file ASN.1 parsing",
	"github.com/foxboron/go-tpm-keyfiles → golang.org/x/crypto/cryptobyte/asn1":                       "TPM key file ASN.1 parsing",
	"github.com/foxboron/go-tpm-keyfiles → golang.org/x/crypto/hkdf":                                  "TPM key derivation (HKDF)",
	"github.com/google/s2a-go/internal/record/internal/aeadcrypter → golang.org/x/crypto/chacha20poly1305": "Google S2A TLS (ChaCha20-Poly1305)",
	"github.com/google/s2a-go/internal/record/internal/halfconn → golang.org/x/crypto/cryptobyte":          "Google S2A TLS record parsing",
	"github.com/google/s2a-go/internal/record/internal/halfconn → golang.org/x/crypto/hkdf":               "Google S2A TLS key derivation",

	// --- ocsp — MongoDB TLS certificate status checking ---
	"go.mongodb.org/mongo-driver/v2/x/mongo/driver/ocsp → golang.org/x/crypto/ocsp": "MongoDB OCSP TLS cert validation",
}

// rootPackage is the starting point for dependency chain resolution.
const rootPackage = "github.com/elastic/elastic-agent/internal/edot/otelcol/components"

type xcryptoPkg struct {
	ImportPath string   `json:"ImportPath"`
	Imports    []string `json:"Imports"`
	Standard   bool     `json:"Standard"`
}

type xcryptoViolation struct {
	importer string
	imported string
}

func runDepScan(t *testing.T) (violations []xcryptoViolation, importGraph map[string][]string) {
	t.Helper()
	cmd := exec.Command("go", "list", "-json", "-deps", "-tags", "requirefips", ".")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	dec := json.NewDecoder(bytes.NewReader(out))
	importGraph = make(map[string][]string)
	for {
		var p xcryptoPkg
		if err := dec.Decode(&p); err == io.EOF {
			break
		} else if err != nil {
			t.Fatalf("decode package: %v", err)
		}
		importGraph[p.ImportPath] = p.Imports
		if p.Standard {
			continue
		}
		// Skip x/crypto packages importing other x/crypto packages (internal).
		if strings.HasPrefix(p.ImportPath, "golang.org/x/crypto/") {
			continue
		}
		for _, imp := range p.Imports {
			if strings.HasPrefix(imp, "golang.org/x/crypto/") {
				violations = append(violations, xcryptoViolation{p.ImportPath, imp})
			}
		}
	}
	return
}

// shortestChain returns the shortest path from `from` to `to` in the import
// graph (forward edges: package → packages it imports). Returns nil if no path.
func shortestChain(from, to string, importGraph map[string][]string) []string {
	type node struct {
		pkg   string
		chain []string
	}
	if from == to {
		return []string{from}
	}
	visited := map[string]bool{from: true}
	queue := []node{{from, []string{from}}}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, imp := range importGraph[cur.pkg] {
			if visited[imp] {
				continue
			}
			chain := make([]string, len(cur.chain)+1)
			copy(chain, cur.chain)
			chain[len(cur.chain)] = imp
			if imp == to {
				return chain
			}
			visited[imp] = true
			queue = append(queue, node{imp, chain})
		}
	}
	return nil
}

func formatChain(chain []string) string {
	return strings.Join(chain, "\n      → ")
}

// TestFIPSFullyCompliant reports all x/crypto violations with their full
// dependency chain and fails on any violation not present in knownViolations.
func TestFIPSFullyCompliant(t *testing.T) {
	violations, importGraph := runDepScan(t)

	found := make(map[string]bool, len(violations))
	for _, v := range violations {
		key := fmt.Sprintf("%s → %s", v.importer, v.imported)
		found[key] = true

		chain := shortestChain(rootPackage, v.importer, importGraph)
		if chain == nil {
			chain = []string{v.importer}
		}
		chain = append(chain, v.imported)

		note, known := knownViolations[key]
		if !known {
			t.Errorf("NEW x/crypto violation — add to knownViolations or remove the dependency:\n      → %s",
				formatChain(chain))
		} else {
			t.Logf("violation [%s]:\n      → %s\n      fix: %s",
				v.imported[len("golang.org/x/crypto/"):], formatChain(chain), note)
		}
	}

	// Detect stale entries whose violation has already been fixed.
	for key := range knownViolations {
		if !found[key] {
			t.Errorf("stale knownViolations entry (no longer in dep tree — remove it): %s", key)
		}
	}
}
