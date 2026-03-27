// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build windows

package manager

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"testing"

	"github.com/Microsoft/go-winio"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-libs/api/npipe"
)

// startTestServer creates an HTTP server listening on a Windows named pipe.
// It returns the http.Client configured to dial that pipe and a cleanup function.
func startTestServer(t *testing.T, handler http.Handler) (*http.Client, func()) {
	t.Helper()
	pipeName := fmt.Sprintf(`\\.\pipe\elastic-agent-test-%s`, t.Name())

	listener, err := winio.ListenPipe(pipeName, nil)
	require.NoError(t, err)

	server := &http.Server{Handler: handler}
	go func() {
		_ = server.Serve(listener)
	}()

	client := &http.Client{
		Transport: &http.Transport{
			DialContext: npipe.DialContext(pipeName),
		},
	}

	cleanup := func() {
		_ = server.Close()
	}

	return client, cleanup
}

// nonExistentClient returns an http.Client that dials a non-existent named pipe.
func nonExistentClient(t *testing.T) *http.Client {
	t.Helper()
	pipeName := `\\.\pipe\elastic-agent-test-nonexistent`
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return winio.DialPipeContext(ctx, pipeName)
			},
		},
	}
}
