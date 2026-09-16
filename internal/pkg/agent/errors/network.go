// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package errors

import (
	"context"
	"net"
	"syscall"
)

// IsNetworkError reports whether err is a failure to reach a remote endpoint
// (connection refused/reset, unreachable host, DNS failure or timeout) as opposed to
// an answer from the remote endpoint.
//
// Use it to tell "the remote endpoint could not be reached" apart from "the remote
// endpoint rejected the request", which usually decide whether an operation is worth
// retrying. Note that TLS failures are not network errors: a completed connection whose
// certificate is rejected is an answer about the configuration, not about reachability.
func IsNetworkError(err error) bool {
	if err == nil {
		return false
	}

	for _, syscallErr := range []error{
		syscall.ECONNREFUSED,
		syscall.ECONNRESET,
		syscall.ECONNABORTED,
		syscall.EHOSTUNREACH,
		syscall.ENETUNREACH,
		syscall.ENETDOWN,
		syscall.ETIMEDOUT,
		syscall.EPIPE,
	} {
		if Is(err, syscallErr) {
			return true
		}
	}

	if Is(err, context.DeadlineExceeded) {
		return true
	}

	var dnsErr *net.DNSError
	if As(err, &dnsErr) {
		return true
	}

	// Covers dial/read/write failures that are not reported through one of the
	// errno values above (which is the case on Windows, for example).
	var opErr *net.OpError
	if As(err, &opErr) {
		return true
	}

	var netErr net.Error
	if As(err, &netErr) && netErr.Timeout() {
		return true
	}

	return false
}
