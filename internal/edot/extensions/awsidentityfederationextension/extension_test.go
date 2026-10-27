// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package awsidentityfederationextension

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/component/componenttest"
	"go.opentelemetry.io/collector/extension"
	"go.uber.org/zap"

	"github.com/elastic/beats/v7/x-pack/libbeat/common/identityfederation"
)

const testRoleARN = "arn:aws:iam::123456789012:role/ElasticWorkloadIdentity-test"

func TestConfigValidate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     Config
		wantErr error
	}{
		{name: "missing role_arn", cfg: Config{}, wantErr: errMissingRoleARN},
		{name: "negative duration", cfg: Config{RoleARN: testRoleARN, Duration: -time.Minute}, wantErr: errNegativeDuration},
		{name: "duration below the STS minimum", cfg: Config{RoleARN: testRoleARN, Duration: 5 * time.Minute}, wantErr: errDurationTooShort},
		{name: "valid with duration", cfg: Config{RoleARN: testRoleARN, Duration: time.Hour}},
		{name: "valid without duration", cfg: Config{RoleARN: testRoleARN}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.Validate()
			if tc.wantErr == nil {
				require.NoError(t, err)
				return
			}
			require.ErrorIs(t, err, tc.wantErr)
		})
	}
}

func TestResolveIssuerSettings(t *testing.T) {
	t.Run("falls back to the controller environment", func(t *testing.T) {
		t.Setenv(identityfederation.WIIIssuerURLEnvVar, "https://wii.example.com")
		t.Setenv(identityfederation.WIISSLCertFileEnvVar, "/env/client.crt")
		t.Setenv(identityfederation.WIISSLKeyFileEnvVar, "/env/client.key")

		got, err := (&Config{RoleARN: testRoleARN}).resolveIssuerSettings()
		require.NoError(t, err)
		assert.Equal(t, issuerSettings{issuerURL: "https://wii.example.com", certFile: "/env/client.crt", keyFile: "/env/client.key"}, got)
	})

	t.Run("explicit configuration wins over the environment", func(t *testing.T) {
		t.Setenv(identityfederation.WIIIssuerURLEnvVar, "https://wii.example.com")
		t.Setenv(identityfederation.WIISSLCertFileEnvVar, "/env/client.crt")
		t.Setenv(identityfederation.WIISSLKeyFileEnvVar, "/env/client.key")

		cfg := &Config{RoleARN: testRoleARN, IssuerURL: "https://wii.override", CertFile: "/cfg/client.crt", KeyFile: "/cfg/client.key"}
		got, err := cfg.resolveIssuerSettings()
		require.NoError(t, err)
		assert.Equal(t, issuerSettings{issuerURL: "https://wii.override", certFile: "/cfg/client.crt", keyFile: "/cfg/client.key"}, got)
	})

	t.Run("missing issuer URL", func(t *testing.T) {
		clearWIIEnv(t)
		_, err := (&Config{RoleARN: testRoleARN, CertFile: "/cfg/client.crt", KeyFile: "/cfg/client.key"}).resolveIssuerSettings()
		require.ErrorIs(t, err, errMissingIssuerURL)
	})

	t.Run("missing client certificate", func(t *testing.T) {
		clearWIIEnv(t)
		_, err := (&Config{RoleARN: testRoleARN, IssuerURL: "https://wii.example.com", CertFile: "/cfg/client.crt"}).resolveIssuerSettings()
		require.ErrorIs(t, err, errMissingClientCerts)
	})
}

func TestFactoryLifecycle(t *testing.T) {
	t.Setenv(identityfederation.WIIIssuerURLEnvVar, "https://wii.example.com")
	t.Setenv(identityfederation.WIISSLCertFileEnvVar, "/env/client.crt")
	t.Setenv(identityfederation.WIISSLKeyFileEnvVar, "/env/client.key")

	factory := NewFactory()
	cfg := factory.CreateDefaultConfig().(*Config)
	cfg.RoleARN = testRoleARN
	require.NoError(t, cfg.Validate())
	settings := extension.Settings{
		ID:                component.NewID(factory.Type()),
		TelemetrySettings: componenttest.NewNopTelemetrySettings(),
		BuildInfo:         component.NewDefaultBuildInfo(),
	}

	ext, err := factory.Create(context.Background(), settings, cfg)
	require.NoError(t, err)
	require.NoError(t, ext.Start(context.Background(), componenttest.NewNopHost()))
	assert.NotNil(t, ext.(Provider).GetCredentialsProvider())
	require.NoError(t, ext.Shutdown(context.Background()))
}

func TestStartFailsWithoutIssuer(t *testing.T) {
	clearWIIEnv(t)
	ext := newExtension(&Config{RoleARN: testRoleARN}, zap.NewNop())
	err := ext.Start(context.Background(), componenttest.NewNopHost())
	require.ErrorIs(t, err, errMissingIssuerURL)
	assert.Nil(t, ext.GetCredentialsProvider())
}

func TestStartRejectsInvalidIssuerURL(t *testing.T) {
	clearWIIEnv(t)
	cfg := &Config{RoleARN: testRoleARN, IssuerURL: "http://wii.example.com", CertFile: "/cfg/client.crt", KeyFile: "/cfg/client.key"}
	err := newExtension(cfg, zap.NewNop()).Start(context.Background(), componenttest.NewNopHost())
	require.ErrorContains(t, err, "must use the https scheme")
}

// TestExchangesWorkloadIdentityForAWSCredentials runs the full chain against a fake
// mTLS issuer and a stubbed STS endpoint: the JWT minted by the issuer must be
// presented verbatim to AssumeRoleWithWebIdentity on the configured role, without an
// ExternalId, and the resulting session must be cached.
func TestExchangesWorkloadIdentityForAWSCredentials(t *testing.T) {
	pki := newTestPKI(t)
	const jwt = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJwcm9qZWN0OnRlc3QifQ.signature"

	var issuerCalls atomic.Int32
	issuer := newIssuerServer(t, pki, func(w http.ResponseWriter, r *http.Request) {
		issuerCalls.Add(1)
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/token", r.URL.Path)
		var body struct {
			Aud string `json:"aud"`
		}
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		assert.Equal(t, stsAudience, body.Aud)
		require.NotEmpty(t, r.TLS.PeerCertificates, "the issuer must receive the client certificate")
		assert.Equal(t, "wii-test-client", r.TLS.PeerCertificates[0].Subject.CommonName)

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(tokenResponse(jwt, time.Now().Add(time.Hour)))
	})

	var stsCalls atomic.Int32
	stsStub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		stsCalls.Add(1)
		require.NoError(t, r.ParseForm())
		assert.Equal(t, "AssumeRoleWithWebIdentity", r.PostForm.Get("Action"))
		assert.Equal(t, testRoleARN, r.PostForm.Get("RoleArn"))
		assert.Equal(t, jwt, r.PostForm.Get("WebIdentityToken"))
		assert.Equal(t, "elastic-agentless", r.PostForm.Get("RoleSessionName"))
		assert.Equal(t, "3600", r.PostForm.Get("DurationSeconds"))
		assert.Empty(t, r.PostForm.Get("ExternalId"), "the direct-trust flow must not send an ExternalId")
		assert.Empty(t, r.Header.Get("Authorization"), "AssumeRoleWithWebIdentity is an unsigned call")

		w.Header().Set("Content-Type", "text/xml")
		_, _ = fmt.Fprintf(w, assumeRoleWithWebIdentityResponse, time.Now().Add(time.Hour).UTC().Format(time.RFC3339))
	}))
	t.Cleanup(stsStub.Close)

	// Route STS to the stub and isolate the SDK from the host's AWS configuration.
	t.Setenv("AWS_ENDPOINT_URL_STS", stsStub.URL)
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	t.Setenv("AWS_CONFIG_FILE", filepath.Join(t.TempDir(), "missing-config"))
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", filepath.Join(t.TempDir(), "missing-credentials"))
	for _, name := range []string{"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_PROFILE", "AWS_REGION", "AWS_DEFAULT_REGION"} {
		t.Setenv(name, "")
	}
	// The environment the agentless controller injects into the pod.
	t.Setenv(identityfederation.WIIIssuerURLEnvVar, issuer.URL)
	t.Setenv(identityfederation.WIISSLCertFileEnvVar, pki.clientCertFile)
	t.Setenv(identityfederation.WIISSLKeyFileEnvVar, pki.clientKeyFile)
	t.Setenv(identityfederation.WIISSLCAFileEnvVar, pki.caFile)

	cfg := &Config{RoleARN: testRoleARN, SessionName: "elastic-agentless", Duration: time.Hour, STSRegion: "eu-west-1"}
	require.NoError(t, cfg.Validate())
	ext := newExtension(cfg, zap.NewNop())
	require.NoError(t, ext.Start(context.Background(), componenttest.NewNopHost()))
	t.Cleanup(func() { require.NoError(t, ext.Shutdown(context.Background())) })

	provider := ext.GetCredentialsProvider()
	require.NotNil(t, provider)
	creds, err := provider.Retrieve(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "ASIATESTACCESSKEY", creds.AccessKeyID)
	assert.Equal(t, "test-secret-access-key", creds.SecretAccessKey)
	assert.Equal(t, "test-session-token", creds.SessionToken)
	assert.True(t, creds.CanExpire)

	// The session is cached until it nears expiry: no second issuer or STS round trip.
	_, err = provider.Retrieve(context.Background())
	require.NoError(t, err)
	assert.Equal(t, int32(1), issuerCalls.Load())
	assert.Equal(t, int32(1), stsCalls.Load())
}

func clearWIIEnv(t *testing.T) {
	t.Helper()
	for _, name := range []string{
		identityfederation.WIIIssuerURLEnvVar,
		identityfederation.WIISSLCertFileEnvVar,
		identityfederation.WIISSLKeyFileEnvVar,
		identityfederation.WIISSLCAFileEnvVar,
	} {
		t.Setenv(name, "")
	}
}

// assumeRoleWithWebIdentityResponse is the STS query-protocol response body; the
// single %s is the session expiration in RFC 3339.
const assumeRoleWithWebIdentityResponse = `<AssumeRoleWithWebIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <AssumeRoleWithWebIdentityResult>
    <SubjectFromWebIdentityToken>project:test</SubjectFromWebIdentityToken>
    <Audience>sts.amazonaws.com</Audience>
    <AssumedRoleUser>
      <Arn>arn:aws:sts::123456789012:assumed-role/ElasticWorkloadIdentity-test/elastic-agentless</Arn>
      <AssumedRoleId>AROATEST:elastic-agentless</AssumedRoleId>
    </AssumedRoleUser>
    <Credentials>
      <AccessKeyId>ASIATESTACCESSKEY</AccessKeyId>
      <SecretAccessKey>test-secret-access-key</SecretAccessKey>
      <SessionToken>test-session-token</SessionToken>
      <Expiration>%s</Expiration>
    </Credentials>
    <Provider>workload-identity-issuer</Provider>
  </AssumeRoleWithWebIdentityResult>
  <ResponseMetadata>
    <RequestId>00000000-0000-0000-0000-000000000000</RequestId>
  </ResponseMetadata>
</AssumeRoleWithWebIdentityResponse>`

func tokenResponse(token string, expiresAt time.Time) []byte {
	body, _ := json.Marshal(map[string]any{"token": token, "expires_at": expiresAt.Unix()})
	return body
}

// testPKI holds a throwaway CA with one server leaf (for the fake issuer) and one
// client leaf written to disk (what the agentless controller mounts into the pod).
type testPKI struct {
	serverTLS      *tls.Config
	caFile         string
	clientCertFile string
	clientKeyFile  string
}

func newTestPKI(t *testing.T) testPKI {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "wii-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	caCert, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})

	newLeaf := func(serial int64, cn string, usage x509.ExtKeyUsage) (tls.Certificate, []byte, []byte) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		template := &x509.Certificate{
			SerialNumber: big.NewInt(serial),
			Subject:      pkix.Name{CommonName: cn},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{usage},
			DNSNames:     []string{"localhost"},
			IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		}
		der, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
		require.NoError(t, err)
		keyDER, err := x509.MarshalECPrivateKey(key)
		require.NoError(t, err)
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
		cert, err := tls.X509KeyPair(certPEM, keyPEM)
		require.NoError(t, err)
		return cert, certPEM, keyPEM
	}
	serverCert, _, _ := newLeaf(2, "wii-test-server", x509.ExtKeyUsageServerAuth)
	_, clientCertPEM, clientKeyPEM := newLeaf(3, "wii-test-client", x509.ExtKeyUsageClientAuth)

	dir := t.TempDir()
	caFile := filepath.Join(dir, "ca.crt")
	certFile := filepath.Join(dir, "wii-client.crt")
	keyFile := filepath.Join(dir, "wii-client.key")
	require.NoError(t, os.WriteFile(caFile, caPEM, 0o600))
	require.NoError(t, os.WriteFile(certFile, clientCertPEM, 0o600))
	require.NoError(t, os.WriteFile(keyFile, clientKeyPEM, 0o600))

	clientPool := x509.NewCertPool()
	clientPool.AddCert(caCert)
	return testPKI{
		serverTLS: &tls.Config{
			Certificates: []tls.Certificate{serverCert},
			ClientAuth:   tls.RequireAndVerifyClientCert,
			ClientCAs:    clientPool,
			MinVersion:   tls.VersionTLS12,
		},
		caFile:         caFile,
		clientCertFile: certFile,
		clientKeyFile:  keyFile,
	}
}

// newIssuerServer starts a fake workload-identity-issuer that requires the client
// certificate issued by the test CA.
func newIssuerServer(t *testing.T, pki testPKI, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(handler)
	srv.TLS = pki.serverTLS
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}
