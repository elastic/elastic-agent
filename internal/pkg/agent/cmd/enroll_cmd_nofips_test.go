// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build !requirefips

package cmd

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-libs/testing/certutil"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/enroll"
	"github.com/elastic/elastic-agent/internal/pkg/cli"
	"github.com/elastic/elastic-agent/internal/pkg/testutils"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

// Test_Enroll_mTLS tests enrolling with encrypted private keys
// It was moved from enroll_cmd_test.go TestEnroll
// TODO: Move back when FIPS distributions support encryped private keys
func Test_Enroll_mTLS(t *testing.T) {
	testutils.InitStorage(t)
	skipCreateSecret := runtime.GOOS == "darwin"

	log, _ := logger.New("tst", false)

	agentCertPassphrase := "a really secure passphrase"
	passphrasePath := filepath.Join(t.TempDir(), "passphrase")
	err := os.WriteFile(
		passphrasePath,
		[]byte(agentCertPassphrase),
		0666)
	require.NoError(t, err,
		"could not write agent child certificate key passphrase to temp directory")

	tlsCfg, _, agentCertPathPair, fleetRootPathPair, _ :=
		mTLSServer(t, agentCertPassphrase)

	mockHandlerCalled := false
	mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mockHandlerCalled = true
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`
{
    "action": "created",
    "item": {
       "id": "a9328860-ec54-11e9-93c4-d72ab8a69391",
        "active": true,
        "policy_id": "69f3f5a0-ec52-11e9-93c4-d72ab8a69391",
        "type": "PERMANENT",
        "enrolled_at": "2019-10-11T18:26:37.158Z",
        "user_provided_metadata": {
						"custom": "customize"
				},
        "local_metadata": {
            "platform": "linux",
            "version": "8.0.0"
        },
        "actions": [],
        "access_api_key": "my-access-api-key"
    }
}`))
	})

	s := httptest.NewUnstartedServer(mockHandler)
	s.TLS = tlsCfg
	s.StartTLS()
	defer s.Close()

	store := &mockStore{}
	enrollOptions := enroll.EnrollOptions{
		CAs:               []string{string(fleetRootPathPair.Cert)},
		Certificate:       string(agentCertPathPair.Cert),
		Key:               string(agentCertPathPair.Key),
		KeyPassphrasePath: passphrasePath,

		URL:                  s.URL,
		EnrollAPIKey:         "my-enrollment-api-key",
		UserProvidedMetadata: map[string]interface{}{"custom": "customize"},
		SkipCreateSecret:     skipCreateSecret,
		SkipDaemonRestart:    true,
	}
	cmd, err := newEnrollCmd(
		log,
		&enrollOptions,
		"",
		store,
		nil,
	)
	require.NoError(t, err, "could not create enroll command")

	streams, _, _, _ := cli.NewTestingIOStreams()
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancel()

	err = cmd.Execute(ctx, streams)
	require.NoError(t, err, "enroll command returned and unexpected error")

	fleetCfg, err := readConfig(store.Content)
	require.NoError(t, err, "could not read fleet config from store")

	assert.True(t, mockHandlerCalled, "mock handler should have been called")
	fleetTLS := fleetCfg.Client.Transport.TLS

	require.NotNil(t, fleetTLS, `fleet client TLS config should have been set`)
	assert.Equal(t, s.URL, fmt.Sprintf("%s://%s",
		fleetCfg.Client.Protocol, fleetCfg.Client.Host))
	assert.Equal(t, enrollOptions.CAs, fleetTLS.CAs)
	assert.Equal(t,
		enrollOptions.Certificate, fleetTLS.Certificate.Certificate)
	assert.Equal(t, enrollOptions.Key, fleetTLS.Certificate.Key)
	assert.Equal(t,
		enrollOptions.KeyPassphrasePath, fleetTLS.Certificate.PassphrasePath)
}

// mTLSServer generates the necessary certificates and tls.Config for a mTLS
// server. If agentPassphrase is given, it'll encrypt the agent's client
// certificate key.
// It returns the *tls.Config to be used with httptest.NewUnstartedServer,
// the agentRootPair, agentChildPair, fleetRootPathPair, fleetCertPathPair.
// Theirs Cert and Key values are the path to the respective certificate and
// certificate key in PEM format.
func mTLSServer(t *testing.T, agentPassphrase string) (
	*tls.Config, certutil.Pair, certutil.Pair, certutil.Pair, certutil.Pair) {

	dir := t.TempDir()

	// generate certificates
	agentRootPair, agentCertPair, err := certutil.NewRootAndChildCerts()
	require.NoError(t, err, "could not create agent's root CA and child certificate")

	// encrypt keys if needed
	if agentPassphrase != "" {
		agentChildDERKey, _ := pem.Decode(agentCertPair.Key)
		require.NoError(t, err, "could not create tls.Certificates from child certificate")

		encPem, err := x509.EncryptPEMBlock( //nolint:staticcheck // we need to drop support for this, but while we don't, it needs to be tested.
			rand.Reader,
			"EC PRIVATE KEY",
			agentChildDERKey.Bytes,
			[]byte(agentPassphrase),
			x509.PEMCipherAES128)
		require.NoError(t, err, "failed encrypting agent child certificate key block")

		agentCertPair.Key = pem.EncodeToMemory(encPem)
	}

	agentRootPathPair := savePair(t, dir, "agent_ca", agentRootPair)
	agentCertPathPair := savePair(t, dir, "agent_cert", agentCertPair)

	fleetRootPair, fleetChildPair, err := certutil.NewRootAndChildCerts()
	require.NoError(t, err, "could not create fleet-server's root CA and child certificate")
	fleetRootPathPair := savePair(t, dir, "fleet_ca", fleetRootPair)
	fleetCertPathPair := savePair(t, dir, "fleet_cert", fleetChildPair)

	// configure server's TLS
	fleetRootCertPool := x509.NewCertPool()
	fleetRootCertPool.AppendCertsFromPEM(fleetRootPair.Cert)
	cert, err := tls.X509KeyPair(fleetChildPair.Cert, fleetChildPair.Key)
	require.NoError(t, err, "could not create tls.Certificates from child certificate")

	agentRootCertPool := x509.NewCertPool()
	agentRootCertPool.AppendCertsFromPEM(agentRootPair.Cert)

	cfg := &tls.Config{
		RootCAs:      fleetRootCertPool,
		Certificates: []tls.Certificate{cert},
		ClientCAs:    agentRootCertPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}

	return cfg, agentRootPathPair, agentCertPathPair, fleetRootPathPair, fleetCertPathPair
}

// savePair saves the key pair on {dest}/{name}.pem and {dest}/{name}_key.pem
func savePair(t *testing.T, dest string, name string, pair certutil.Pair) certutil.Pair {
	certPath := filepath.Join(dest, name+".pem")
	err := os.WriteFile(certPath, pair.Cert, 0o600)
	require.NoErrorf(t, err, "could not save %s certificate", name)

	keyPath := filepath.Join(dest, name+"_key.pem")
	err = os.WriteFile(keyPath, pair.Key, 0o600)
	require.NoErrorf(t, err, "could not save %s certificate key", name)

	return certutil.Pair{
		Cert: []byte(certPath),
		Key:  []byte(keyPath),
	}
}
