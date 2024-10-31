// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package proxytest

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-libs/testing/certutil"
)

func TestProxy(t *testing.T) {

	// Eagerly create objects for TLS setup with CA and server certificate
	caCertificate, _, caPrivateKey, err := createCaCertificate()
	require.NoError(t, err, "error creating CA cert and key")

	serverCert, serverCertBytes, serverPrivateKey, err := createCertificateSignedByCA(caCertificate, caPrivateKey)
	require.NoError(t, err, "error creating server certificate")

	caCertPool := x509.NewCertPool()
	caCertPool.AddCert(caCertificate)

	type setup struct {
		fakeBackendServer      *httptest.Server
		generateTestHttpClient func(t *testing.T, proxy *Proxy) *http.Client
	}
	type testRequest struct {
		method string
		url    string
		body   io.Reader
	}
	type testcase struct {
		name          string
		setup         setup
		proxyOptions  []Option
		proxyStartTLS bool
		request       testRequest
		wantErr       assert.ErrorAssertionFunc
		assertFunc    func(t *testing.T, proxy *Proxy, resp *http.Response)
	}

	testcases := []testcase{
		{
			name: "Basic scenario, no TLS",
			setup: setup{
				fakeBackendServer:      createFakeBackendServer(),
				generateTestHttpClient: nil,
			},
			proxyOptions:  nil,
			proxyStartTLS: false,
			request: testRequest{
				method: http.MethodGet,
				url:    "http://somehost:1234/some/path/here",
				body:   nil,
			},
			wantErr: assert.NoError,
			assertFunc: func(t *testing.T, proxy *Proxy, resp *http.Response) {
				assert.Equal(t, http.StatusOK, resp.StatusCode)
				if assert.NotEmpty(t, proxy.ProxiedRequests(), "proxy should have captured at least 1 request") {
					assert.Contains(t, proxy.ProxiedRequests()[0], "/some/path/here")
				}
			},
		},
		{
			name: "TLS scenario, server cert validation",
			setup: setup{
				fakeBackendServer: createFakeBackendServer(),
				generateTestHttpClient: func(t *testing.T, proxy *Proxy) *http.Client {
					proxyURL, err := url.Parse(proxy.URL)
					require.NoErrorf(t, err, "failed to parse proxy URL %q", proxy.URL)

					// Client trusting the proxy cert CA
					return &http.Client{
						Transport: &http.Transport{
							Proxy: http.ProxyURL(proxyURL),
							TLSClientConfig: &tls.Config{
								RootCAs:    caCertPool,
								MinVersion: tls.VersionTLS12,
							},
						},
					}
				},
			},
			proxyOptions: []Option{
				WithServerTLSConfig(&tls.Config{
					ClientCAs: caCertPool,
					Certificates: []tls.Certificate{{
						Certificate: [][]byte{serverCertBytes},
						PrivateKey:  serverPrivateKey,
						Leaf:        serverCert,
					}},
					MinVersion: tls.VersionTLS12,
				}),
			},
			proxyStartTLS: true,
			request: testRequest{
				method: http.MethodGet,
				url:    "http://somehost:1234/some/path/here",
				body:   nil,
			},
			wantErr: assert.NoError,
			assertFunc: func(t *testing.T, proxy *Proxy, resp *http.Response) {
				assert.Equal(t, http.StatusOK, resp.StatusCode)
				if assert.NotEmpty(t, proxy.ProxiedRequests(), "proxy should have captured at least 1 request") {
					assert.Contains(t, proxy.ProxiedRequests()[0], "/some/path/here")
				}
			},
		},
		{
			name: "mTLS scenario, client and server cert validation",
			setup: setup{
				fakeBackendServer: createFakeBackendServer(),
				generateTestHttpClient: func(t *testing.T, proxy *Proxy) *http.Client {
					proxyURL, err := url.Parse(proxy.URL)
					require.NoErrorf(t, err, "failed to parse proxy URL %q", proxy.URL)

					// Client certificate
					clientCert, clientCertBytes, clientPrivateKey, err := createCertificateSignedByCA(caCertificate, caPrivateKey)
					require.NoError(t, err, "error creating client certificate")

					// Client with its own certificate and trusting the proxy cert CA
					return &http.Client{
						Transport: &http.Transport{
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
				},
			},
			proxyOptions: []Option{
				// require client authentication and verify cert
				WithServerTLSConfig(&tls.Config{
					ClientCAs:  caCertPool,
					ClientAuth: tls.RequireAndVerifyClientCert,
					Certificates: []tls.Certificate{{
						Certificate: [][]byte{serverCertBytes},
						PrivateKey:  serverPrivateKey,
						Leaf:        serverCert,
					}},
					MinVersion: tls.VersionTLS12,
				}),
			},
			proxyStartTLS: true,
			request: testRequest{
				method: http.MethodGet,
				url:    "http://somehost:1234/some/path/here",
				body:   nil,
			},
			wantErr: assert.NoError,
			assertFunc: func(t *testing.T, proxy *Proxy, resp *http.Response) {
				assert.Equal(t, http.StatusOK, resp.StatusCode)
				if assert.NotEmpty(t, proxy.ProxiedRequests(), "proxy should have captured at least 1 request") {
					assert.Contains(t, proxy.ProxiedRequests()[0], "/some/path/here")
				}
			},
		},
	}

	for _, tt := range testcases {
		t.Run(tt.name, func(t *testing.T) {
			var proxyOpts []Option

			if tt.setup.fakeBackendServer != nil {
				defer tt.setup.fakeBackendServer.Close()
				serverURL, err := url.Parse(tt.setup.fakeBackendServer.URL)
				require.NoErrorf(t, err, "failed to parse test HTTP server URL %q", tt.setup.fakeBackendServer.URL)
				proxyOpts = append(proxyOpts, WithRewriteFn(func(u *url.URL) {
					// redirect the requests on the proxy itself
					u.Host = serverURL.Host
				}))
			}

			proxyOpts = append(proxyOpts, tt.proxyOptions...)
			proxy := New(t, proxyOpts...)

			if tt.proxyStartTLS {
				t.Log("Starting proxytest with TLS")
				err = proxy.StartTLS()
			} else {
				t.Log("Starting proxytest without TLS")
				err = proxy.Start()
			}

			require.NoError(t, err, "error starting proxytest")

			defer proxy.Close()

			proxyURL, err := url.Parse(proxy.URL)
			require.NoErrorf(t, err, "failed to parse proxy URL %q", proxy.URL)

			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			req, err := http.NewRequestWithContext(ctx, tt.request.method, tt.request.url, tt.request.body)
			require.NoError(t, err, "error creating request")

			var client *http.Client
			if tt.setup.generateTestHttpClient != nil {
				client = tt.setup.generateTestHttpClient(t, proxy)
			} else {
				// basic HTTP client using the proxy
				client = &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
			}

			resp, err := client.Do(req)
			if resp != nil {
				defer resp.Body.Close()
			}
			if tt.wantErr(t, err, "unexpected error return value") && tt.assertFunc != nil {
				tt.assertFunc(t, proxy, resp)
			}
		})
	}

}

func TestHTTPSProxy(t *testing.T) {
	targetHost := "not-a-server.co"
	proxy, client, target := prepareMTLSProxyAndTargetServer(t, targetHost)
	t.Cleanup(func() {
		proxy.Close()
		target.Close()
	})

	tcs := []struct {
		name   string
		target string
		// assertFn should not close the response body
		assertFn func(*testing.T, *http.Response, error)
	}{
		{
			name:   "successful_request",
			target: "https://" + targetHost,
			assertFn: func(t *testing.T, got *http.Response, err error) {
				if !assert.Equal(t, http.StatusOK, got.StatusCode, "unexpected status code") {
					body, err := io.ReadAll(got.Body)
					if err != nil {
						t.Logf("could not read response body")
						t.FailNow()
					}
					_ = got.Body.Close()

					t.Logf("request body: %s", string(body))
				}

			},
		},
		{
			name:   "request_failure",
			target: "https://any.not.target.will.do",
			assertFn: func(t *testing.T, got *http.Response, err error) {
				assert.NoError(t, err, "request to an invalid host should not fail, but succeed with a HTTP error")
				assert.Equal(t, http.StatusBadGateway, got.StatusCode)

				body, err := io.ReadAll(got.Body)
				require.NoError(t, err, "failed reading response body")
				assert.Contains(t, string(body), "failed performing request to target")
			},
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			t.Logf("making request to %q using proxy %q", tc.target, proxy.URL)

			got, err := client.Get(tc.target) //nolint:noctx // it's a test
			require.NoError(t, err, "request should have succeeded")
			defer got.Body.Close()

			// assertFn should not close the response body
			tc.assertFn(t, got, err)
		})
	}
}

func prepareMTLSProxyAndTargetServer(t *testing.T, targetHost string) (*Proxy, http.Client, *httptest.Server) {
	serverCAKey, serverCACert, _, err := certutil.NewRootCA()
	require.NoError(t, err, "error creating root CA")

	serverCert, _, err := certutil.GenerateChildCert(
		"localhost",
		[]net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback, net.IPv6zero},
		serverCAKey,
		serverCACert)
	require.NoError(t, err, "error creating server certificate")
	serverCACertPool := x509.NewCertPool()
	serverCACertPool.AddCert(serverCACert)

	proxyCAKey, proxyCACert, _, err := certutil.NewRootCA()
	require.NoError(t, err, "error creating root CA")

	proxyCert, _, err := certutil.GenerateChildCert(
		"localhost",
		[]net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback, net.IPv6zero},
		proxyCAKey,
		proxyCACert)
	require.NoError(t, err, "error creating server certificate")
	proxyCACertPool := x509.NewCertPool()
	proxyCACertPool.AddCert(proxyCACert)

	clientCAKey, clientCACert, _, err := certutil.NewRootCA()
	require.NoError(t, err, "error creating root CA")
	clientCACertPool := x509.NewCertPool()
	clientCACertPool.AddCert(clientCACert)

	clientCert, _, err := certutil.GenerateChildCert(
		"localhost",
		[]net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback, net.IPv6zero},
		clientCAKey,
		clientCACert)
	require.NoError(t, err, "error creating server certificate")

	server := httptest.NewUnstartedServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("It works!"))
		}))
	server.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{*serverCert},
	}
	server.StartTLS()
	t.Logf("target server running on %s", server.URL)

	proxy := New(t,
		WithVerboseLog(),
		WithRequestLog("https", t.Logf),
		WithRewrite(targetHost+":443", server.URL[8:]),
		WithMITMCA(proxyCAKey, proxyCACert),
		WithHTTPClient(&http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					MinVersion: tls.VersionTLS13,
					RootCAs:    serverCACertPool,
				},
			},
		}),
		WithServerTLSConfig(&tls.Config{
			Certificates: []tls.Certificate{*proxyCert},
			ClientCAs:    clientCACertPool,
			ClientAuth:   tls.RequireAndVerifyClientCert,
			MinVersion:   tls.VersionTLS13,
		}))
	err = proxy.StartTLS()
	require.NoError(t, err, "error starting proxy")
	t.Logf("proxy running on %s", proxy.URL)

	proxyURL, err := url.Parse(proxy.URL)
	require.NoErrorf(t, err, "failed to parse proxy URL %q", proxy.URL)

	client := http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{
				RootCAs:      proxyCACertPool,
				Certificates: []tls.Certificate{*clientCert},
				MinVersion:   tls.VersionTLS12,
			},
		},
	}

	return proxy, client, server
}

func createFakeBackendServer() *httptest.Server {
	handlerF := func(writer http.ResponseWriter, request *http.Request) {
		// always return HTTP 200
		writer.WriteHeader(http.StatusOK)
	}

	fakeBackendHTTPServer := httptest.NewServer(http.HandlerFunc(handlerF))
	return fakeBackendHTTPServer
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
func createCertificateSignedByCA(caCert *x509.Certificate, caPrivateKey *rsa.PrivateKey) (cert *x509.Certificate, certBytes []byte, privateKey *rsa.PrivateKey, err error) {
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
