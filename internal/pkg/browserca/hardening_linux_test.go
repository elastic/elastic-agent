// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package browserca

import (
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStartDoesNotProbeUnconfiguredHome(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv(browserUserEnv, "no-such-browser-user-17931")
	fd, err := syscall.InotifyInit1(syscall.IN_NONBLOCK | syscall.IN_CLOEXEC)
	require.NoError(t, err)
	defer syscall.Close(fd)
	_, err = syscall.InotifyAddWatch(fd, home, syscall.IN_CREATE|syscall.IN_DELETE|syscall.IN_MODIFY|syscall.IN_ATTRIB)
	require.NoError(t, err)
	log := &testLog{}
	assert.Empty(t, start(t.Context(), log, Config{}, time.Second))
	assert.Empty(t, log.logs)
	_, err = syscall.Read(fd, make([]byte, 4096))
	assert.ErrorIs(t, err, syscall.EAGAIN, "unconfigured startup must not write to HOME")
}

func TestStartReturnsBrowserHomeWithoutChangingEnvironment(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires non-root HOME fallback")
	}
	if _, err := exec.LookPath("certutil"); err != nil {
		t.Skip("requires certutil")
	}
	cur, err := user.Current()
	require.NoError(t, err)
	t.Setenv("HOME", "/proc")
	t.Setenv(browserUserEnv, cur.Username)
	cfg := Config{CertificateAuthorities: []string{filepath.Join(t.TempDir(), "missing-ca.pem")}}
	cfg.CertificateReload.Enabled = new(bool)
	assert.Equal(t, cur.HomeDir, start(t.Context(), &testLog{}, cfg, time.Second))
	assert.Equal(t, "/proc", os.Getenv("HOME"))
}
