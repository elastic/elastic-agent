// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package control

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

func TestDialContextBlocking_Success(t *testing.T) {
	buffer := bufconn.Listen(1024 * 1024)
	defer buffer.Close()

	server := grpc.NewServer()
	go func() {
		if err := server.Serve(buffer); err != nil {
			t.Logf("Server serve error: %v", err)
		}
	}()
	defer server.Stop()

	// Test successful connection
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	conn, err := DialContextBlocking(ctx, "bufconn",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			return buffer.Dial()
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)

	require.NoError(t, err, "DialContextBlocking failed")
	defer conn.Close()

	// Verify connection is ready
	state := conn.GetState()
	assert.Equal(t, connectivity.Ready, state, "Expected connection state to be Ready")
}

func TestDialContextBlocking_ContextCancellation(t *testing.T) {
	// Create a context that cancels immediately
	ctx, cancel := context.WithCancel(t.Context())
	cancel() // Cancel immediately

	// Try to establish connection with cancelled context
	conn, err := DialContextBlocking(ctx, "unreachable:12345",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)

	// Should return an error due to context cancellation
	require.Error(t, err, "Expected DialContextBlocking to fail with cancelled context")
	if conn != nil {
		conn.Close()
	}

	assert.Equal(t, context.Canceled, err, "Expected context.Canceled error")
}

func TestDialContextBlocking_InvalidTarget(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 1*time.Second)
	defer cancel()

	// Try to connect to an invalid target
	conn, err := DialContextBlocking(ctx, "invalid-scheme://invalid-target",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)

	// Should return an error
	require.Error(t, err, "Expected DialContextBlocking to fail with invalid target")
	if conn != nil {
		conn.Close()
	}
}

func TestDialContextBlocking_Timeout(t *testing.T) {
	// Create a very short timeout
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Millisecond)
	defer cancel()

	// Try to connect to a non-existent service
	conn, err := DialContextBlocking(ctx, "127.0.0.1:1",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)

	// Should return an error due to timeout
	require.Error(t, err, "Expected DialContextBlocking to fail with timeout")
	if conn != nil {
		conn.Close()
	}

	assert.Equal(t, context.DeadlineExceeded, err, "Expected context.DeadlineExceeded error")
}
