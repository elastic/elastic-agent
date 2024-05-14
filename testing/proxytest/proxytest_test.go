// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package proxytest

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProxy_BasicScenario(t *testing.T) {
	handlerF := func(writer http.ResponseWriter, request *http.Request) {
		// always return HTTP 200
		writer.WriteHeader(http.StatusOK)
	}

	fakeBackendHTTPServer := httptest.NewServer(http.HandlerFunc(handlerF))
	defer fakeBackendHTTPServer.Close()

	serverURL, err := url.Parse(fakeBackendHTTPServer.URL)
	require.NoErrorf(t, err, "failed to parse test HTTP server URL %q", fakeBackendHTTPServer.URL)

	proxy := New(t, WithRewriteFn(func(u *url.URL) {
		// redirect the requests on the proxy itself
		u.Host = serverURL.Host
	}))
	proxy.Start()
	defer proxy.Close()

	proxyURL, err := url.Parse(proxy.URL)
	require.NoErrorf(t, err, "failed to parse proxy URL %q", proxy.URL)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://somehost:1234/some/path/here", nil)
	require.NoError(t, err, "error creating request")
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	resp, err := client.Do(req)
	assert.NoError(t, err, "proxied request should not fail")
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	require.NotEmpty(t, proxy.ProxiedRequests(), "proxy should have captured at least 1 request")
	assert.Contains(t, proxy.ProxiedRequests()[0], serverURL.Host+"/some/path/here")
}

func TestProxy_BasicTLSScenario(t *testing.T) {
	handlerF := func(writer http.ResponseWriter, request *http.Request) {
		// always return HTTP 200
		writer.WriteHeader(http.StatusOK)
	}

	fakeBackendHTTPServer := httptest.NewServer(http.HandlerFunc(handlerF))
	defer fakeBackendHTTPServer.Close()

	serverURL, err := url.Parse(fakeBackendHTTPServer.URL)
	require.NoErrorf(t, err, "failed to parse test HTTP server URL %q", fakeBackendHTTPServer.URL)

	// TLS setup with CA and server certificate
	caCertificate, _, caPrivateKey, err := createCaCertificate()
	require.NoError(t, err, "error creating CA cert and key")

	serverCert, serverCertBytes, serverPrivateKey, err := createCertificate(caCertificate, caPrivateKey)
	require.NoError(t, err, "error creating server certificate")

	caCertPool := x509.NewCertPool()
	caCertPool.AddCert(caCertificate)

	proxy := New(t, WithRewriteFn(func(u *url.URL) {
		u.Host = serverURL.Host
	}), WithServerTLSConfig(&tls.Config{
		ClientCAs: caCertPool,
		Certificates: []tls.Certificate{{
			Certificate:                  [][]byte{serverCertBytes},
			PrivateKey:                   serverPrivateKey,
			SupportedSignatureAlgorithms: nil,
			OCSPStaple:                   nil,
			SignedCertificateTimestamps:  nil,
			Leaf:                         serverCert,
		}},
		MinVersion: tls.VersionTLS12,
	}))
	proxy.StartTLS()
	defer proxy.Close()

	t.Logf("Proxy URL: %q", proxy.URL)

	proxyURL, err := url.Parse(proxy.URL)
	require.NoErrorf(t, err, "failed to parse proxy URL %q", proxy.URL)

	// Add the root CA to the client as well
	client := &http.Client{Transport: &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
		TLSClientConfig: &tls.Config{
			RootCAs:    caCertPool,
			MinVersion: tls.VersionTLS12,
		},
	}}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://somehost:1234/some/path/here", nil)
	require.NoError(t, err, "error creating request")
	resp, err := client.Do(req)
	assert.NoError(t, err, "proxied request should not fail")
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	require.NotEmpty(t, proxy.ProxiedRequests(), "proxy should have captured at least 1 request")
	assert.Contains(t, proxy.ProxiedRequests()[0], serverURL.Host+"/some/path/here")
}

func TestProxy_mTLSScenario(t *testing.T) {
	handlerF := func(writer http.ResponseWriter, request *http.Request) {
		// always return HTTP 200
		writer.WriteHeader(http.StatusOK)
	}

	fakeBackendHTTPServer := httptest.NewServer(http.HandlerFunc(handlerF))
	defer fakeBackendHTTPServer.Close()

	serverURL, err := url.Parse(fakeBackendHTTPServer.URL)
	require.NoErrorf(t, err, "failed to parse test HTTP server URL %q", fakeBackendHTTPServer.URL)

	// TLS setup with CA and server certificate
	caCertificate, _, caPrivateKey, err := createCaCertificate()
	require.NoError(t, err, "error creating CA cert and key")

	serverCert, serverCertBytes, serverPrivateKey, err := createCertificate(caCertificate, caPrivateKey)
	require.NoError(t, err, "error creating server certificate")

	caCertPool := x509.NewCertPool()
	caCertPool.AddCert(caCertificate)

	proxy := New(t, WithRewriteFn(func(u *url.URL) {
		u.Host = serverURL.Host
	}), WithServerTLSConfig(&tls.Config{
		ClientCAs:  caCertPool,
		ClientAuth: tls.RequireAndVerifyClientCert,
		Certificates: []tls.Certificate{{
			Certificate:                  [][]byte{serverCertBytes},
			PrivateKey:                   serverPrivateKey,
			SupportedSignatureAlgorithms: nil,
			OCSPStaple:                   nil,
			SignedCertificateTimestamps:  nil,
			Leaf:                         serverCert,
		}},
		MinVersion: tls.VersionTLS12,
	}))
	proxy.StartTLS()
	defer proxy.Close()

	t.Logf("Proxy URL: %q", proxy.URL)

	proxyURL, err := url.Parse(proxy.URL)
	require.NoErrorf(t, err, "failed to parse proxy URL %q", proxy.URL)

	// Client certificate
	clientCert, clientCertBytes, clientPrivateKey, err := createCertificate(caCertificate, caPrivateKey)
	require.NoError(t, err, "error creating client certificate")

	// Add the root CA to the client as well
	client := &http.Client{Transport: &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
		TLSClientConfig: &tls.Config{
			RootCAs: caCertPool,
			Certificates: []tls.Certificate{
				{
					Certificate: [][]byte{clientCertBytes},
					PrivateKey:  clientPrivateKey,
					Leaf:        clientCert,
				},
			},
			MinVersion: tls.VersionTLS12,
		},
	}}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://somehost:1234/some/path/here", nil)
	require.NoError(t, err, "error creating request")
	resp, err := client.Do(req)
	assert.NoError(t, err, "proxied request should not fail")
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	require.NotEmpty(t, proxy.ProxiedRequests(), "proxy should have captured at least 1 request")
	assert.Contains(t, proxy.ProxiedRequests()[0], serverURL.Host+"/some/path/here")
}

// utility function to create a CA cert and related key for tests. It returns certificate and key as PEM-encoded blocks
func createCaCertificate() (cert *x509.Certificate, certBytes []byte, privateKey *rsa.PrivateKey, err error) {
	// set up our CA certificate
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(2023),
		Subject: pkix.Name{
			Organization:  []string{"Elastic Agent Testing Company, INC."},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{"San Francisco"},
			StreetAddress: []string{"Golden Gate Bridge"},
			PostalCode:    []string{"94016"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(0, 0, 1),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	// create our private and public key
	caPrivateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, nil, nil, err
	}

	// create the CA
	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &caPrivateKey.PublicKey, caPrivateKey)
	if err != nil {
		return nil, nil, nil, err
	}

	cert, err = x509.ParseCertificate(caBytes)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("error parsing generated CA cert: %w", err)
	}

	return cert, caBytes, caPrivateKey, nil
}

// utility function to create a new certificate signed by a CA and related key for tests.
// Both paramenters and returned certificate and key are PEM-encoded blocks.
func createCertificate(caCert *x509.Certificate, caPrivateKey *rsa.PrivateKey) (cert *x509.Certificate, certBytes []byte, privateKey *rsa.PrivateKey, err error) {
	certTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2024),
		Subject: pkix.Name{
			Organization:  []string{"Elastic Agent Testing Company, INC."},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{"San Francisco"},
			StreetAddress: []string{"Golden Gate Bridge"},
			PostalCode:    []string{"94016"},
		},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback, net.IPv6zero},
		DNSNames:     []string{"localhost"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(0, 0, 1),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	certPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, nil, nil, err
	}

	certBytes, err = x509.CreateCertificate(rand.Reader, certTemplate, caCert, &certPrivKey.PublicKey, caPrivateKey)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("error creating new certificate: %w", err)
	}

	cert, err = x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("error parsing new certificate: %w", err)
	}

	return cert, certBytes, certPrivKey, nil
}
