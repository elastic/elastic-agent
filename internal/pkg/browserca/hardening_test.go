// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build !windows

package browserca

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRejectedCAInputsPreserveTrust(t *testing.T) {
	for _, kind := range []string{"fifo", "symlink to fifo", "oversized file", "total size", "too many paths", "too many files", "too many entries", "too many certificates"} {
		t.Run(kind, func(t *testing.T) {
			m, fake, dir, _ := setup(t)
			write(t, dir, "ca.pem", newCA(t, "original"))
			require.NoError(t, m.reconcile(t.Context()))
			before := fake.nicknames()
			switch kind {
			case "fifo", "symlink to fifo":
				fifo := filepath.Join(t.TempDir(), "fifo")
				require.NoError(t, syscall.Mkfifo(fifo, 0o600))
				if kind == "symlink to fifo" {
					link := filepath.Join(dir, "bad.pem")
					require.NoError(t, os.Symlink(fifo, link))
				} else {
					m.paths = []string{fifo}
				}
			case "oversized file":
				write(t, dir, "large.pem", strings.Repeat("x", maxCAFileBytes+1))
			case "total size":
				for _, name := range []string{"a.pem", "b.pem", "c.pem", "d.pem"} {
					write(t, dir, name, strings.Repeat("x", maxCAFileBytes))
				}
			case "too many paths":
				m.paths = make([]string, maxCAFiles+1)
			case "too many files":
				for range maxCAFiles {
					f, err := os.CreateTemp(dir, "extra-*.pem")
					require.NoError(t, err)
					require.NoError(t, f.Close())
				}
			case "too many certificates":
				var bundle strings.Builder
				for range maxCertificates {
					bundle.WriteString(newCA(t, "extra"))
				}
				write(t, dir, "bundle.pem", bundle.String())
			case "too many entries":
				for i := range maxDirectoryEntries {
					f, err := os.CreateTemp(dir, "unrelated-*")
					require.NoError(t, err, "entry %d", i)
					require.NoError(t, f.Close())
				}
			}
			require.Error(t, m.reconcile(t.Context()))
			assert.Equal(t, before, fake.nicknames(), "rejected input must not change existing trust")
		})
	}
}

func TestReadCAFileChecksOpenedDescriptorAndLimit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ca.pem")
	require.NoError(t, syscall.Mkfifo(path, 0o600))
	_, err := readCAFile(path, maxCAFileBytes)
	require.ErrorContains(t, err, "not a regular file")
	require.NoError(t, os.Remove(path))
	require.NoError(t, os.WriteFile(path, []byte("1234"), 0o600))
	data, err := readCAFile(path, 4)
	require.NoError(t, err)
	assert.Equal(t, "1234", string(data))
	_, err = readCAFile(path, 3)
	require.ErrorContains(t, err, "byte limit")
}

func TestFailedImportPreservesOldTrust(t *testing.T) {
	m, fake, dir, _ := setup(t)
	write(t, dir, "ca.pem", newCA(t, "old"))
	require.NoError(t, m.reconcile(t.Context()))
	before := fake.nicknames()
	write(t, dir, "ca.pem", newCA(t, "new"))
	fake.fail = func(op string, _ []string) error {
		if op == "-A" {
			return context.DeadlineExceeded
		}
		return nil
	}
	require.ErrorIs(t, m.reconcile(t.Context()), context.DeadlineExceeded)
	assert.Equal(t, before, fake.nicknames())
	fake.fail = nil
	require.NoError(t, m.reconcile(t.Context()))
	assert.NotEqual(t, before, fake.nicknames())
}

func TestExecRunnerDeadline(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	started := time.Now()
	_, err := execRunner("/bin/sh", nil)(ctx, nil, "-c", "exec sleep 60")
	require.ErrorIs(t, err, context.DeadlineExceeded)
	assert.Less(t, time.Since(started), 2*time.Second)
}

func TestExecRunnerCommandTimeout(t *testing.T) {
	started := time.Now()
	_, err := execRunner("/bin/sh", nil)(t.Context(), nil, "-c", "exec sleep 60")
	require.ErrorIs(t, err, context.DeadlineExceeded)
	assert.Less(t, time.Since(started), commandTimeout+2*time.Second)
}

func TestExecRunnerOutputLimit(t *testing.T) {
	out, err := execRunner("/bin/sh", nil)(t.Context(), nil, "-c", "head -c 5000000 /dev/zero")
	require.ErrorContains(t, err, "output exceeds")
	assert.Len(t, out, maxCommandOutput)
}

func TestStartBoundsStartupWait(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv(browserUserEnv, "")
	bin := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(bin, "certutil"), []byte("#!/bin/sh\nexec /bin/sleep 60\n"), 0o700))
	t.Setenv("PATH", bin)
	dir := t.TempDir()
	write(t, dir, "ca.pem", newCA(t, "ca"))
	cfg := Config{CertificateAuthorities: []string{dir}}
	cfg.CertificateReload.Enabled = new(bool)
	log := &testLog{}
	started := time.Now()
	assert.Empty(t, start(t.Context(), log, cfg, 50*time.Millisecond))
	assert.Less(t, time.Since(started), time.Second)
	assert.Equal(t, home, os.Getenv("HOME"))
	require.Eventually(t, func() bool { return log.has("custom CA certificates not imported") }, 2*time.Second, 10*time.Millisecond)
}

func TestCleanupWithoutManagedCertificatesDoesNotRepairOwnership(t *testing.T) {
	m, _, _, _ := setup(t)
	m.paths = nil
	m.owner = &owner{uid: 12345, gid: 12345}
	m.inspect = func(context.Context, []byte, ...string) ([]byte, error) { return []byte("user-certificate C,,"), nil }
	m.certs = func(context.Context, []byte, ...string) ([]byte, error) {
		return nil, errors.New("must not mutate store")
	}
	require.NoError(t, m.reconcile(t.Context()))
	assert.NoDirExists(t, filepath.Join(m.home, ".pki"))
}
