// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

// This shows an example of how to generate a SSH RSA Private/Public key pair and save it locally

package runner

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// newSSHPrivateKey creates RSA private key
func newSSHPrivateKey() (*rsa.PrivateKey, error) {
	pk, err := rsa.GenerateKey(rand.Reader, 2056)
	if err != nil {
		return nil, err
	}
	err = pk.Validate()
	if err != nil {
		return nil, err
	}
	return pk, nil
}

// sshEncodeToPEM encodes private key to PEM format
func sshEncodeToPEM(privateKey *rsa.PrivateKey) []byte {
	der := x509.MarshalPKCS1PrivateKey(privateKey)
	privBlock := pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: nil,
		Bytes:   der,
	}
	return pem.EncodeToMemory(&privBlock)
}

// newSSHPublicKey returns bytes for writing to .pub file
func newSSHPublicKey(pk *rsa.PublicKey) ([]byte, error) {
	pub, err := ssh.NewPublicKey(pk)
	if err != nil {
		return nil, err
	}
	return ssh.MarshalAuthorizedKey(pub), nil
}

type fileContentsOpts struct {
	command string
}

// FileContentsOpt provides an option to modify how fetching files from the remote host work.
type FileContentsOpt func(opts *fileContentsOpts)

// WithContentFetchCommand changes the command to use for fetching the file contents.
func WithContentFetchCommand(command string) FileContentsOpt {
	return func(opts *fileContentsOpts) {
		opts.command = command
	}
}

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

type sshClient struct {
	ip       string
	username string
	auth     ssh.AuthMethod

	c *ssh.Client
}

// NewSSHClient creates a new SSH client connection to the host.
func NewSSHClient(ip string, username string, sshAuth ssh.AuthMethod) SSHClient {
	return &sshClient{
		ip:       ip,
		username: username,
		auth:     sshAuth,
	}
}

// Connect connects to the host.
func (s *sshClient) Connect(ctx context.Context) error {
	var lastErr error
	for {
		if ctx.Err() != nil {
			if lastErr == nil {
				return ctx.Err()
			}
			return lastErr
		}
		config := &ssh.ClientConfig{
			User:            s.username,
			HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // it's the tests framework test
			Auth:            []ssh.AuthMethod{s.auth},
			Timeout:         30 * time.Second,
		}
		client, err := ssh.Dial("tcp", net.JoinHostPort(s.ip, "22"), config)
		if err == nil {
			s.c = client
			return nil
		}
		lastErr = err
	}
}

// ConnectWithTimeout connects to the host with a timeout.
func (s *sshClient) ConnectWithTimeout(ctx context.Context, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return s.Connect(ctx)
}

// Close closes the client.
func (s *sshClient) Close() error {
	if s.c != nil {
		err := s.c.Close()
		s.c = nil
		return err
	}
	return nil
}

// Reconnect disconnects and reconnected to the host.
func (s *sshClient) Reconnect(ctx context.Context) error {
	_ = s.Close()
	return s.Connect(ctx)
}

// ReconnectWithTimeout disconnects and reconnected to the host with a timeout.
func (s *sshClient) ReconnectWithTimeout(ctx context.Context, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return s.Reconnect(ctx)
}

// NewSession opens a new Session for this host.
func (s *sshClient) NewSession() (*ssh.Session, error) {
	return s.c.NewSession()
}

// Exec runs a command on the host.
func (s *sshClient) Exec(ctx context.Context, cmd string, args []string, stdin io.Reader) ([]byte, []byte, error) {
	if ctx.Err() != nil {
		return nil, nil, ctx.Err()
	}

	cmdArgs := []string{cmd}
	cmdArgs = append(cmdArgs, args...)
	cmdStr := strings.Join(cmdArgs, " ")
	session, err := s.NewSession()
	if err != nil {
		return nil, nil, fmt.Errorf("could not create new SSH session: %w", err)
	}
	defer session.Close()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	session.Stdout = &stdout
	session.Stderr = &stderr
	if stdin != nil {
		session.Stdin = stdin
	}
	err = session.Run(cmdStr)
	if err != nil {
		return stdout.Bytes(), stderr.Bytes(), fmt.Errorf("could not run %q though SSH: %w",
			cmdStr, err)
	}
	return stdout.Bytes(), stderr.Bytes(), err
}

// ExecWithRetry runs the command on loop waiting the interval between calls
func (s *sshClient) ExecWithRetry(ctx context.Context, cmd string, args []string, interval time.Duration) ([]byte, []byte, error) {
	var lastErr error
	var lastStdout []byte
	var lastStderr []byte
	for {
		// the length of time for running the command is not blocked on the interval
		// don't create a new context with the interval as its timeout
		stdout, stderr, err := s.Exec(ctx, cmd, args, nil)
		if err == nil {
			return stdout, stderr, nil
		}
		lastErr = err
		lastStdout = stdout
		lastStderr = stderr

		// wait for the interval or ctx to be cancelled
		select {
		case <-ctx.Done():
			if lastErr != nil {
				return lastStdout, lastStderr, lastErr
			}
			return nil, nil, ctx.Err()
		case <-time.After(interval):
		}
	}
}

// Copy copies the filePath to the host at dest.
func (s *sshClient) Copy(filePath string, dest string) error {
	f, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer f.Close()
	fs, err := f.Stat()
	if err != nil {
		return err
	}

	session, err := s.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()

	w, err := session.StdinPipe()
	if err != nil {
		return err
	}

	cmd := fmt.Sprintf("scp -t %s", dest)
	if err := session.Start(cmd); err != nil {
		_ = w.Close()
		return err
	}

	errCh := make(chan error)
	go func() {
		errCh <- session.Wait()
	}()

	_, err = fmt.Fprintf(w, "C%#o %d %s\n", fs.Mode().Perm(), fs.Size(), dest)
	if err != nil {
		_ = w.Close()
		<-errCh
		return err
	}
	_, err = io.Copy(w, f)
	if err != nil {
		_ = w.Close()
		<-errCh
		return err
	}
	_, _ = fmt.Fprint(w, "\x00")
	_ = w.Close()
	return <-errCh
}

// GetFileContents returns the file content.
func (s *sshClient) GetFileContents(ctx context.Context, filename string, opts ...FileContentsOpt) ([]byte, error) {
	var stdout bytes.Buffer
	err := s.GetFileContentsOutput(ctx, filename, &stdout, opts...)
	if err != nil {
		return nil, err
	}
	return stdout.Bytes(), nil
}

// GetFileContentsOutput returns the file content writing into output.
func (s *sshClient) GetFileContentsOutput(ctx context.Context, filename string, output io.Writer, opts ...FileContentsOpt) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}

	var fco fileContentsOpts
	fco.command = "cat"
	for _, opt := range opts {
		opt(&fco)
	}

	session, err := s.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()

	session.Stdout = output
	err = session.Run(fmt.Sprintf("%s %s", fco.command, filename))
	if err != nil {
		return err
	}
	return nil
}
