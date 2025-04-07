// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build !requirefips

package cmd

import (
	"context"
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

	"github.com/elastic/elastic-agent/internal/pkg/cli"
	"github.com/elastic/elastic-agent/internal/pkg/testutils"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

// Test_Enroll_mTLS tests enrolling with encrypted private keys
// It was moved from enroll_cmd_test.go TestEnroll
// TODO: Move back when FIPS distributions support encryped private keys
func Test_Enroll_mTLS(t *testing.T) {
	testutils.InitStorage(t)
	skipCreateSecret := false
	if runtime.GOOS == "darwin" {
		skipCreateSecret = true
	}

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
	enrollOptions := enrollCmdOption{
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
