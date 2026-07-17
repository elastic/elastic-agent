// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build requirefips

package cmd_test

import (
	"testing"

	"github.com/elastic/elastic-agent-libs/testing/fipsscan"
)

var knownViolations = map[string]map[string][]fipsscan.KnownViolation{
	"github.com/elastic/elastic-agent": {
		// elastic/gokrb5 is an Elastic fork of jcmturner/gokrb5 used for Kerberos auth.
		"github.com/elastic/gokrb5/v8": {
			{Imported: "github.com/jcmturner", Reason: "Elastic gokrb5 fork depends on jcmturner gofork (ASN.1, pbkdf2) and aescts (AES-CBC-CTS)"},
			{Imported: "golang.org/x/crypto", Reason: "Kerberos RC4-HMAC (md4) and key derivation (pbkdf2); x/crypto not FIPS-certified"},
		},
		// artifact/download uses x/crypto/openpgp for GPG artifact signature verification.
		"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact/download": {
			{Imported: "golang.org/x/crypto", Reason: "GPG signature verification of upgrade artifacts requires openpgp"},
		},
		// go-tpm-keyfiles uses x/crypto for TPM key file parsing (ChaCha20, HKDF, ASN.1).
		"github.com/foxboron/go-tpm-keyfiles": {
			{Imported: "golang.org/x/crypto", Reason: "TPM key file parsing uses ChaCha20, HKDF, cryptobyte; no FIPS-certified alternative in go-tpm-keyfiles"},
		},
	},
}

func TestFIPSCompliance(t *testing.T) {
	fipsscan.CheckModule(t, []string{"./..."}, nil, nil, knownViolations)
}
