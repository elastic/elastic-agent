// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package errors

import (
	"context"
	"crypto/x509"
	goerrors "errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIsNetworkError(t *testing.T) {
	dialErr := &net.OpError{
		Op:  "dial",
		Net: "tcp",
		Err: os.NewSyscallError("connect", syscall.ECONNREFUSED),
	}

	for name, tc := range map[string]struct {
		err      error
		expected bool
	}{
		"nil": {
			err:      nil,
			expected: false,
		},
		"connection refused": {
			err:      dialErr,
			expected: true,
		},
		"connection refused wrapped the way an http client reports it": {
			// the agent error wraps the joined per-host errors of the remote client,
			// which in turn wrap what net/http returned.
			err: New(
				fmt.Errorf("all hosts failed: %w",
					goerrors.Join(fmt.Errorf("requester 0/1 to host localhost:8221 errored: %w",
						&url.Error{Op: "Post", URL: "https://localhost:8221/api/fleet/agents/id/acks", Err: dialErr}))),
				"fail to ack to fleet", TypeNetwork),
			expected: true,
		},
		"connection reset": {
			err:      &net.OpError{Op: "read", Net: "tcp", Err: os.NewSyscallError("read", syscall.ECONNRESET)},
			expected: true,
		},
		"no route to host": {
			err:      &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", syscall.EHOSTUNREACH)},
			expected: true,
		},
		"dns failure": {
			err:      &net.DNSError{Err: "no such host", Name: "fleet.example.com", IsNotFound: true},
			expected: true,
		},
		"timeout": {
			err:      &url.Error{Op: "Post", URL: "https://localhost:8221", Err: &net.DNSError{Err: "i/o timeout", IsTimeout: true}},
			expected: true,
		},
		"context deadline exceeded": {
			err:      fmt.Errorf("request failed: %w", context.DeadlineExceeded),
			expected: true,
		},
		"certificate verification failure is not a network error": {
			// the endpoint was reached, it is the configuration that is wrong
			err: &url.Error{Op: "Post", URL: "https://localhost:8221", Err: &x509.CertificateInvalidError{
				Reason: x509.Expired,
				Detail: "certificate has expired",
			}},
			expected: false,
		},
		"arbitrary error": {
			err:      goerrors.New("some failure"),
			expected: false,
		},
	} {
		t.Run(name, func(t *testing.T) {
			require.Equal(t, tc.expected, IsNetworkError(tc.err))
		})
	}
}
