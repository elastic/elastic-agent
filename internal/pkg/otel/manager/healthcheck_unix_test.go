// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build !windows

package manager

import (
	"context"
	"net"
	"net/http"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// startTestServer creates an HTTP server listening on a Unix domain socket in a temp directory.
// It returns the http.Client configured to dial that socket and a cleanup function.
func startTestServer(t *testing.T, handler http.Handler) (*http.Client, func()) {
	t.Helper()
	sockPath := filepath.Join(t.TempDir(), "test.sock")
	listener, err := net.Listen("unix", sockPath)
	require.NoError(t, err)

	server := &http.Server{Handler: handler}
	go func() {
		_ = server.Serve(listener)
	}()

	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", sockPath)
			},
		},
	}

	cleanup := func() {
		_ = server.Close()
	}

	return client, cleanup
}

// nonExistentClient returns an http.Client that dials a non-existent Unix socket.
func nonExistentClient(t *testing.T) *http.Client {
	t.Helper()
	sockPath := filepath.Join(t.TempDir(), "nonexistent.sock")
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", sockPath)
			},
		},
	}
}
