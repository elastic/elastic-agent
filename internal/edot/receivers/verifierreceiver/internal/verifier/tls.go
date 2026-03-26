// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package verifier // import "github.com/elastic/elastic-agent/internal/edot/receivers/verifierreceiver/internal/verifier"

import (
	"crypto/tls"
	"net/http"
)

// fipsCurves is the set of FIPS-approved elliptic curves (NIST SP 800-186).
// X25519 (Curve25519) is excluded because it is not a NIST curve and is
// therefore not FIPS 140-2/3 approved. P-256 is offered first as it is the
// most widely negotiated curve for ECDHE; P-384 is included as a fallback.
var fipsCurves = []tls.CurveID{tls.CurveP256, tls.CurveP384}

// newHTTPClient returns an [*http.Client] with TLS 1.3 as the minimum protocol
// version. TLS 1.3 cipher suites are fixed by the specification and are all
// FIPS-approved, so no explicit cipher list is needed. Key exchange is
// restricted to FIPS-approved NIST curves (P-256, P-384), excluding X25519
// which is not a NIST curve.
//
// Use this for all endpoints that are confirmed to support TLS 1.3:
// AWS STS, Azure Entra ID (login.microsoftonline.com), and all *.googleapis.com.
//
// Full binary-level FIPS compliance also requires building with
// GOEXPERIMENT=systemcrypto (RHEL) or GOEXPERIMENT=boringcrypto, which
// replaces the standard Go crypto library with a FIPS 140-validated
// implementation. The TLS settings here provide defence-in-depth and are
// effective regardless of build mode.
func newHTTPClient() *http.Client {
	var transport *http.Transport
	if t, ok := http.DefaultTransport.(*http.Transport); ok {
		transport = t.Clone()
	} else {
		transport = &http.Transport{}
	}
	transport.TLSClientConfig = &tls.Config{
		MinVersion:       tls.VersionTLS13,
		CurvePreferences: fipsCurves,
	}
	return &http.Client{Transport: transport}
}

// newTLS12HTTPClient returns an [*http.Client] with TLS 1.2 as the minimum
// protocol version, restricted to FIPS-approved cipher suites (AES-GCM with
// ECDHE or RSA key exchange authenticated with SHA-256 or SHA-384) and
// FIPS-approved NIST curves (P-256, P-384).
//
// Use this only for Azure Resource Manager (management.azure.com), whose
// official documentation does not yet confirm TLS 1.3 support.
// Prefer [newHTTPClient] (TLS 1.3) everywhere else.
func newTLS12HTTPClient() *http.Client {
	var transport *http.Transport
	if t, ok := http.DefaultTransport.(*http.Transport); ok {
		transport = t.Clone()
	} else {
		transport = &http.Transport{}
	}
	transport.TLSClientConfig = &tls.Config{
		MinVersion:       tls.VersionTLS12,
		CurvePreferences: fipsCurves,
		// FIPS-approved cipher suites for TLS 1.2.
		// TLS 1.3 suites are not configurable and are all FIPS-approved.
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
		},
	}
	return &http.Client{Transport: transport}
}
