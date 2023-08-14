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

// sshConnect keeps trying to make the SSH connection up until the context is cancelled
func sshConnect(ctx context.Context, ip string, username string, sshAuth ssh.AuthMethod) (*ssh.Client, error) {
	var lastErr error
	for {
		if ctx.Err() != nil {
			if lastErr == nil {
				return nil, ctx.Err()
			}
			return nil, lastErr
		}
		config := &ssh.ClientConfig{
			User:            username,
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
			Auth:            []ssh.AuthMethod{sshAuth},
			Timeout:         30 * time.Second,
		}
		client, err := ssh.Dial("tcp", net.JoinHostPort(ip, "22"), config)
		if err == nil {
			return client, nil
		}
		lastErr = err
	}
}

// sshRunCommand runs a command on the SSH client connection.
// It returns stdout, stderr and an error if any. stdout and stderr might be nil
// if an error happens before running cmd.
func sshRunCommand(ctx context.Context, c *ssh.Client, cmd string, args []string, stdin io.Reader) ([]byte, []byte, error) {
	if ctx.Err() != nil {
		return nil, nil, fmt.Errorf("sshRunCommand: %w", ctx.Err())
	}

	cmdArgs := []string{cmd}
	cmdArgs = append(cmdArgs, args...)
	cmdStr := strings.Join(cmdArgs, " ")
	session, err := c.NewSession()
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

	return stdout.Bytes(), stderr.Bytes(), nil
}

// sshRunCommandWithRetry runs the command on loop waiting the interval between calls
func sshRunCommandWithRetry(ctx context.Context, c *ssh.Client, cmd string, args []string, interval time.Duration) ([]byte, []byte, error) {
	var lastErr error
	var lastStdout []byte
	var lastStderr []byte
	for {
		// the length of time for running the command is not blocked on the interval
		// don't create a new context with the interval as its timeout
		stdout, stderr, err := sshRunCommand(ctx, c, cmd, args, nil)
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

// sshSCP copies the filePath to the destination.
func sshSCP(c *ssh.Client, filePath string, dest string) error {
	f, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer f.Close()
	s, err := f.Stat()
	if err != nil {
		return err
	}

	session, err := c.NewSession()
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

	_, err = fmt.Fprintf(w, "C%#o %d %s\n", s.Mode().Perm(), s.Size(), dest)
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

// sshGetFileContents returns the file content.
func sshGetFileContents(ctx context.Context, c *ssh.Client, filename string) ([]byte, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	session, err := c.NewSession()
	if err != nil {
		return nil, err
	}
	defer session.Close()

	var stdout bytes.Buffer
	session.Stdout = &stdout
	err = session.Run(fmt.Sprintf("cat %s", filename))
	if err != nil {
		return nil, err
	}
	return stdout.Bytes(), nil
}

// sshGetFileContentsOutput writes the file contents into output.
func sshGetFileContentsOutput(ctx context.Context, c *ssh.Client, filename string, output io.Writer) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}

	session, err := c.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()

	session.Stdout = output
	err = session.Run(fmt.Sprintf("cat %s", filename))
	if err != nil {
		return err
	}
	return nil
}
