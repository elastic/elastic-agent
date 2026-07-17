// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build requirefips

package cmd_test

import (
	"testing"

	"github.com/elastic/elastic-agent-libs/testing/fipsscan"
)

var knownViolations = map[string][]fipsscan.KnownViolation{
	"github.com/elastic/elastic-agent": {
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
		// artifact download uses x/crypto/openpgp for GPG signature verification.
		{Importer: "github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact/download", Imported: "golang.org/x/crypto/openpgp"},
		// go-tpm-keyfiles uses x/crypto for TPM key file parsing (ChaCha20, HKDF, ASN.1).
		{Importer: "github.com/foxboron/go-tpm-keyfiles", Imported: "golang.org/x/crypto/chacha20poly1305"},
		{Importer: "github.com/foxboron/go-tpm-keyfiles", Imported: "golang.org/x/crypto/cryptobyte"},
		{Importer: "github.com/foxboron/go-tpm-keyfiles", Imported: "golang.org/x/crypto/cryptobyte/asn1"},
		{Importer: "github.com/foxboron/go-tpm-keyfiles", Imported: "golang.org/x/crypto/hkdf"},
	},
}

func TestFIPSCompliance(t *testing.T) {
	fipsscan.CheckModule(t, "github.com/elastic/elastic-agent", nil, knownViolations)
}
