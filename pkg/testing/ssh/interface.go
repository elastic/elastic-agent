// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package ssh

import (
	"context"
	"io"
	"time"

	"golang.org/x/crypto/ssh"
)

// SSHClient is a *ssh.Client that provides a nice interface to work with.
type SSHClient interface {
	// Connect connects to the host.
	Connect(ctx context.Context) error

	// ConnectWithTimeout connects to the host with a timeout.
	ConnectWithTimeout(ctx context.Context, timeout time.Duration) error

	// Close closes the client.
	Close() error

	// Reconnect disconnects and reconnected to the host.
	Reconnect(ctx context.Context) error

	// ReconnectWithTimeout disconnects and reconnected to the host with a timeout.
	ReconnectWithTimeout(ctx context.Context, timeout time.Duration) error

	// NewSession opens a new Session for this host.
	NewSession() (*ssh.Session, error)

	// Exec runs a command on the host.
	Exec(ctx context.Context, cmd string, args []string, stdin io.Reader) ([]byte, []byte, error)

	// ExecWithRetry runs the command on loop waiting the interval between calls
	ExecWithRetry(ctx context.Context, cmd string, args []string, interval time.Duration) ([]byte, []byte, error)

	// Copy copies the filePath to the host at dest.
	Copy(filePath string, dest string) error

	// GetFileContents returns the file content.
	GetFileContents(ctx context.Context, filename string, opts ...FileContentsOpt) ([]byte, error)

	// GetFileContentsOutput returns the file content writing to output.
	GetFileContentsOutput(ctx context.Context, filename string, output io.Writer, opts ...FileContentsOpt) error
}
