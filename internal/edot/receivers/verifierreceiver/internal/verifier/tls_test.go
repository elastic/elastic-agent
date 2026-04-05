// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

// Tests for FIPS-compliant TLS helper functions and verifier TLS configurations.
// All tests pass under GODEBUG=fips140=only.
// TestNewTLS12HTTPClient_RejectsNonFIPSCipherSuite is skipped in that mode
// because Go's own TLS stack refuses to configure a server with non-FIPS
// cipher suites, making the adversarial server impossible to create.
// All test TLS servers use FIPS-approved curve preferences (P-256, P-384) to
// avoid X25519, which is blocked under GODEBUG=fips140=only.
package verifier

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// isFIPSOnly reports whether GODEBUG=fips140=only is active.
func isFIPSOnly() bool {
	return strings.Contains(os.Getenv("GODEBUG"), "fips140=only")
}

// fipsApprovedTLS12Ciphers is the complete FIPS 140-2/3 approved set of TLS 1.2
// cipher suites. It must mirror the list in newTLS12HTTPClient exactly.
var fipsApprovedTLS12Ciphers = map[uint16]bool{
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:   true,
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: true,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:   true,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: true,
	tls.TLS_RSA_WITH_AES_128_GCM_SHA256:         true,
	tls.TLS_RSA_WITH_AES_256_GCM_SHA384:         true,
}

// generateECDSACert creates a self-signed ECDSA P-256/SHA-256 certificate and
// returns it together with a pool that trusts it. Both P-256 and SHA-256 are
// FIPS-approved, so this helper is safe to call under GODEBUG=fips140=only.
func generateECDSACert(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "verifier-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	require.NoError(t, err)

	parsed, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)
	pool := x509.NewCertPool()
	pool.AddCert(parsed)

	return tlsCert, pool
}

// withTestCA returns a shallow copy of client whose TLS config additionally
// trusts pool. The original TLS version and cipher-suite settings are preserved.
func withTestCA(t *testing.T, client *http.Client, pool *x509.CertPool) *http.Client {
	t.Helper()
	tr, ok := client.Transport.(*http.Transport)
	require.True(t, ok, "client.Transport is not *http.Transport")
	tr = tr.Clone()
	tr.TLSClientConfig = tr.TLSClientConfig.Clone()
	tr.TLSClientConfig.RootCAs = pool
	return &http.Client{Transport: tr}
}

// tlsHandshakeState holds the TLS parameters observed by a test server handler.
type tlsHandshakeState struct {
	Version     uint16
	CipherSuite uint16
}

// capturingHandler returns an HTTP handler and a buffered channel. The handler
// sends the TLS state of the first request to the channel before writing a
// 200 response. Sending before WriteHeader guarantees the channel has data by
// the time client.Get returns.
func capturingHandler() (http.Handler, <-chan tlsHandshakeState) {
	ch := make(chan tlsHandshakeState, 1)
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS != nil {
			select {
			case ch <- tlsHandshakeState{Version: r.TLS.Version, CipherSuite: r.TLS.CipherSuite}:
			default:
			}
		}
		w.WriteHeader(http.StatusOK)
	})
	return h, ch
}

// startTLSServer creates an unstarted httptest server, sets cfg as its TLS
// configuration, starts it, and registers t.Cleanup to close it.
func startTLSServer(t *testing.T, cfg *tls.Config, h http.Handler) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(h)
	srv.TLS = cfg
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// extractTransport returns the *http.Transport from client, failing the test
// if the assertion fails or TLSClientConfig is nil.
func extractTransport(t *testing.T, client *http.Client) *http.Transport {
	t.Helper()
	tr, ok := client.Transport.(*http.Transport)
	require.True(t, ok, "client.Transport is not *http.Transport")
	require.NotNil(t, tr.TLSClientConfig, "TLSClientConfig must not be nil")
	return tr
}

// writeFakeTokenFile writes a placeholder JWT to a temp file and returns its path.
// Used for identity-federation code paths that need a token file to exist.
func writeFakeTokenFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "id_token")
	require.NoError(t, os.WriteFile(path, []byte("fake.jwt.token"), 0600))
	return path
}

// ---------------------------------------------------------------------------
// newHTTPClient — config inspection
// ---------------------------------------------------------------------------

func TestNewHTTPClient_MinVersionIsTLS13(t *testing.T) {
	tr := extractTransport(t, newHTTPClient())
	assert.Equal(t, uint16(tls.VersionTLS13), tr.TLSClientConfig.MinVersion)
}

func TestNewHTTPClient_NoCipherSuiteRestriction(t *testing.T) {
	// TLS 1.3 cipher suites are fixed by the RFC and all FIPS-approved.
	// Setting CipherSuites has no effect on TLS 1.3; it must be left empty.
	tr := extractTransport(t, newHTTPClient())
	assert.Empty(t, tr.TLSClientConfig.CipherSuites,
		"TLS 1.3 cipher suites are fixed by spec — CipherSuites field must be empty")
}

// ---------------------------------------------------------------------------
// newTLS12HTTPClient — config inspection
// ---------------------------------------------------------------------------

func TestNewTLS12HTTPClient_MinVersionIsTLS12(t *testing.T) {
	tr := extractTransport(t, newTLS12HTTPClient())
	assert.Equal(t, uint16(tls.VersionTLS12), tr.TLSClientConfig.MinVersion)
}

func TestNewTLS12HTTPClient_ExactFIPSCipherSuiteList(t *testing.T) {
	tr := extractTransport(t, newTLS12HTTPClient())
	want := []uint16{
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
	}
	assert.Equal(t, want, tr.TLSClientConfig.CipherSuites)
}

func TestNewTLS12HTTPClient_AllCipherSuitesAreFIPSApproved(t *testing.T) {
	tr := extractTransport(t, newTLS12HTTPClient())
	require.NotEmpty(t, tr.TLSClientConfig.CipherSuites)
	for _, cs := range tr.TLSClientConfig.CipherSuites {
		assert.True(t, fipsApprovedTLS12Ciphers[cs],
			"non-FIPS cipher suite found: %s (0x%04x)", tls.CipherSuiteName(cs), cs)
	}
}

// ---------------------------------------------------------------------------
// TLS handshake tests
// ---------------------------------------------------------------------------

// TestNewHTTPClient_NegotiatesTLS13 verifies that newHTTPClient actually
// negotiates TLS 1.3 when the server supports it, not a lower version.
func TestNewHTTPClient_NegotiatesTLS13(t *testing.T) {
	cert, pool := generateECDSACert(t)
	handler, stateCh := capturingHandler()
	// Server supports TLS 1.2 and 1.3; client must still choose 1.3.
	// CurvePreferences is restricted to FIPS-approved curves (P-256, P-384)
	// so the test server avoids X25519, which is blocked under fips140=only.
	srv := startTLSServer(t, &tls.Config{
		Certificates:     []tls.Certificate{cert},
		MinVersion:       tls.VersionTLS12,
		CurvePreferences: []tls.CurveID{tls.CurveP256, tls.CurveP384},
	}, handler)

	resp, err := withTestCA(t, newHTTPClient(), pool).Get(srv.URL)
	require.NoError(t, err)
	resp.Body.Close()

	select {
	case state := <-stateCh:
		assert.Equal(t, uint16(tls.VersionTLS13), state.Version,
			"expected TLS 1.3 to be negotiated, got 0x%04x", state.Version)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for TLS state from test server")
	}
}

// TestNewTLS12HTTPClient_NegotiatesFIPSCipherSuite verifies that
// newTLS12HTTPClient negotiates a FIPS-approved cipher suite when the server
// forces TLS 1.2 (as is the case for management.azure.com).
func TestNewTLS12HTTPClient_NegotiatesFIPSCipherSuite(t *testing.T) {
	cert, pool := generateECDSACert(t)
	handler, stateCh := capturingHandler()
	// CurvePreferences is restricted to FIPS-approved curves (P-256, P-384)
	// so the test server avoids X25519, which is blocked under fips140=only.
	srv := startTLSServer(t, &tls.Config{
		Certificates:     []tls.Certificate{cert},
		MaxVersion:       tls.VersionTLS12,
		CipherSuites:     []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384},
		CurvePreferences: []tls.CurveID{tls.CurveP256, tls.CurveP384},
	}, handler)

	resp, err := withTestCA(t, newTLS12HTTPClient(), pool).Get(srv.URL)
	require.NoError(t, err)
	resp.Body.Close()

	select {
	case state := <-stateCh:
		assert.True(t, fipsApprovedTLS12Ciphers[state.CipherSuite],
			"expected a FIPS-approved cipher suite, got %s (0x%04x)",
			tls.CipherSuiteName(state.CipherSuite), state.CipherSuite)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for TLS state from test server")
	}
}

// TestNewHTTPClient_RejectsTLS12OnlyServer verifies that a TLS 1.3-minimum
// client refuses to connect to a server that only offers TLS 1.2.
// This test passes under GODEBUG=fips140=only because TLS 1.2 is FIPS-approved
// and Go allows configuring a server with MaxVersion=TLS12.
func TestNewHTTPClient_RejectsTLS12OnlyServer(t *testing.T) {
	cert, pool := generateECDSACert(t)
	srv := startTLSServer(t, &tls.Config{
		Certificates:     []tls.Certificate{cert},
		MaxVersion:       tls.VersionTLS12,
		CipherSuites:     []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		CurvePreferences: []tls.CurveID{tls.CurveP256, tls.CurveP384},
	}, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	_, err := withTestCA(t, newHTTPClient(), pool).Get(srv.URL)
	assert.Error(t, err, "TLS 1.3-minimum client must refuse a TLS 1.2-only server")
}

// TestNewTLS12HTTPClient_RejectsNonFIPSCipherSuite verifies that a client
// restricted to FIPS cipher suites fails when the server exclusively offers a
// non-FIPS TLS 1.2 cipher suite (no common cipher → handshake failure).
// Skipped under GODEBUG=fips140=only: Go's TLS stack refuses to configure a
// server with non-FIPS cipher suites in that mode.
func TestNewTLS12HTTPClient_RejectsNonFIPSCipherSuite(t *testing.T) {
	if isFIPSOnly() {
		t.Skip("cannot create a non-FIPS TLS server under GODEBUG=fips140=only")
	}

	cert, pool := generateECDSACert(t)
	// TLS_RSA_WITH_AES_128_CBC_SHA uses CBC+SHA-1 MAC — not FIPS-approved.
	srv := startTLSServer(t, &tls.Config{
		Certificates: []tls.Certificate{cert},
		MaxVersion:   tls.VersionTLS12,
		CipherSuites: []uint16{tls.TLS_RSA_WITH_AES_128_CBC_SHA},
	}, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	_, err := withTestCA(t, newTLS12HTTPClient(), pool).Get(srv.URL)
	assert.Error(t, err,
		"client restricted to FIPS cipher suites must reject a server offering only non-FIPS suites")
}

// ---------------------------------------------------------------------------
// Verifier TLS configuration tests
// ---------------------------------------------------------------------------

// TestAWSVerifier_UsesTLS13Client verifies that NewAWSVerifier wires its HTTP
// client with TLS 1.3 as the minimum version. config.LoadDefaultConfig always
// succeeds regardless of whether AWS credentials are present.
func TestAWSVerifier_UsesTLS13Client(t *testing.T) {
	v, err := NewAWSVerifier(context.Background(), zap.NewNop(), AWSAuthConfig{
		UseDefaultCredentials: true,
	})
	require.NoError(t, err)
	require.True(t, v.configured)
	t.Cleanup(func() { _ = v.Close() })

	tr := extractTransport(t, v.httpClient)
	assert.Equal(t, uint16(tls.VersionTLS13), tr.TLSClientConfig.MinVersion)
	assert.Empty(t, tr.TLSClientConfig.CipherSuites)
}

// TestAzureVerifier_UsesTLS13ForCredentials verifies that NewAzureVerifier
// configures its Entra ID credential client (login.microsoftonline.com) with
// TLS 1.3.  Uses the identity-federation path with a fake token file because
// NewClientAssertionCredential does not make network calls during construction.
func TestAzureVerifier_UsesTLS13ForCredentials(t *testing.T) {
	v, err := NewAzureVerifier(context.Background(), zap.NewNop(), AzureAuthConfig{
		IDTokenFile: writeFakeTokenFile(t),
		TenantID:    "fake-tenant-id",
		ClientID:    "fake-client-id",
	})
	require.NoError(t, err)
	require.True(t, v.configured)
	t.Cleanup(func() { _ = v.Close() })

	tr := extractTransport(t, v.httpClient)
	assert.Equal(t, uint16(tls.VersionTLS13), tr.TLSClientConfig.MinVersion,
		"Entra ID client (login.microsoftonline.com) must require TLS 1.3")
	assert.Empty(t, tr.TLSClientConfig.CipherSuites,
		"TLS 1.3 cipher suites are fixed by spec — no restriction needed")
}

// TestAzureVerifier_UsesTLS12WithFIPSCiphersForARM verifies that NewAzureVerifier
// configures a separate ARM client (management.azure.com) with TLS 1.2 minimum
// and only FIPS-approved cipher suites, because TLS 1.3 support for that
// endpoint is not yet officially documented by Microsoft.
func TestAzureVerifier_UsesTLS12WithFIPSCiphersForARM(t *testing.T) {
	v, err := NewAzureVerifier(context.Background(), zap.NewNop(), AzureAuthConfig{
		IDTokenFile: writeFakeTokenFile(t),
		TenantID:    "fake-tenant-id",
		ClientID:    "fake-client-id",
	})
	require.NoError(t, err)
	require.True(t, v.configured)
	t.Cleanup(func() { _ = v.Close() })

	tr := extractTransport(t, v.armHTTPClient)
	assert.Equal(t, uint16(tls.VersionTLS12), tr.TLSClientConfig.MinVersion,
		"ARM client (management.azure.com) must use TLS 1.2 minimum")
	require.NotEmpty(t, tr.TLSClientConfig.CipherSuites,
		"ARM client must restrict to explicit FIPS cipher suites")
	for _, cs := range tr.TLSClientConfig.CipherSuites {
		assert.True(t, fipsApprovedTLS12Ciphers[cs],
			"non-FIPS cipher suite in ARM client: %s (0x%04x)", tls.CipherSuiteName(cs), cs)
	}
}

// TestAzureVerifier_CredentialsAndARMClientsAreIndependent verifies that the
// two HTTP clients are distinct objects with different TLS configurations,
// proving that Entra ID and ARM requests are independently secured.
func TestAzureVerifier_CredentialsAndARMClientsAreIndependent(t *testing.T) {
	v, err := NewAzureVerifier(context.Background(), zap.NewNop(), AzureAuthConfig{
		IDTokenFile: writeFakeTokenFile(t),
		TenantID:    "fake-tenant-id",
		ClientID:    "fake-client-id",
	})
	require.NoError(t, err)
	require.True(t, v.configured)
	t.Cleanup(func() { _ = v.Close() })

	assert.NotSame(t, v.httpClient, v.armHTTPClient,
		"Entra ID and ARM clients must be separate *http.Client instances")

	credTR := extractTransport(t, v.httpClient)
	armTR := extractTransport(t, v.armHTTPClient)
	assert.NotEqual(t, credTR.TLSClientConfig.MinVersion, armTR.TLSClientConfig.MinVersion,
		"Entra ID client (TLS 1.3) and ARM client (TLS 1.2) must have different MinVersion")
}

// TestGCPVerifier_UsesTLS13Client verifies that NewGCPVerifier configures its
// HTTP client with TLS 1.3 as the minimum version.  Uses the identity-federation
// path; externalaccount.NewTokenSource does not make network calls during
// construction.
func TestGCPVerifier_UsesTLS13Client(t *testing.T) {
	v, err := NewGCPVerifier(context.Background(), zap.NewNop(), GCPAuthConfig{
		IDTokenFile:   writeFakeTokenFile(t),
		Audience:      "//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/pool/providers/provider",
		GlobalRoleARN: "arn:aws:iam::123456789012:role/TestRole",
		ProjectID:     "test-project",
	})
	require.NoError(t, err)
	require.True(t, v.configured)
	t.Cleanup(func() { _ = v.Close() })

	tr := extractTransport(t, v.httpClient)
	assert.Equal(t, uint16(tls.VersionTLS13), tr.TLSClientConfig.MinVersion)
	assert.Empty(t, tr.TLSClientConfig.CipherSuites)
}
