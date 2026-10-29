// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build !windows

package customca

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/pkg/core/logger/loggertest"
)

// newCA returns a self-signed CA certificate in PEM form.
func newCA(t *testing.T, cn string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err, "generating key")
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err, "creating certificate")
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// fakeNSS stands in for certutil and keeps the database in memory.
type fakeNSS struct {
	mu    sync.Mutex
	certs map[string]bool // nicknames in the database
	calls []string        // operations, e.g. "-A custom-ca-..."
	// fail, if set, returns an error for a call: op is the first argument.
	fail func(op string, args []string) error
}

func newFakeNSS() *fakeNSS { return &fakeNSS{certs: map[string]bool{}} }

func (f *fakeNSS) run(_ context.Context, stdin []byte, args ...string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	op := args[0]
	if f.fail != nil {
		if err := f.fail(op, args); err != nil {
			return nil, err
		}
	}
	arg := func(flag string) string {
		for i, a := range args {
			if a == flag && i+1 < len(args) {
				return args[i+1]
			}
		}
		return ""
	}
	switch op {
	case "-N":
		dir := strings.TrimPrefix(arg("-d"), "sql:")
		if err := os.WriteFile(filepath.Join(dir, "cert9.db"), nil, 0o600); err != nil {
			return nil, err
		}
	case "-L":
		var b strings.Builder
		b.WriteString("\nCertificate Nickname                      Trust Attributes\n\n")
		for nick := range f.certs {
			fmt.Fprintf(&b, "%-40s C,,\n", nick)
		}
		f.calls = append(f.calls, "-L")
		return []byte(b.String()), nil
	case "-A":
		if block, _ := pem.Decode(stdin); block == nil || block.Type != "CERTIFICATE" {
			return nil, errors.New("not a certificate")
		}
		f.certs[arg("-n")] = true
		f.calls = append(f.calls, "-A "+arg("-n"))
	case "-D":
		delete(f.certs, arg("-n"))
		f.calls = append(f.calls, "-D "+arg("-n"))
	}
	return nil, nil
}

func (f *fakeNSS) nicknames() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var n []string
	for k := range f.certs {
		n = append(n, k)
	}
	return n
}

func (f *fakeNSS) callsWith(prefix string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var c []string
	for _, call := range f.calls {
		if strings.HasPrefix(call, prefix) {
			c = append(c, call)
		}
	}
	return c
}

func (f *fakeNSS) reset() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = nil
}

type testLog struct {
	mu   sync.Mutex
	logs []string
}

func (l *testLog) Infof(format string, args ...any) { l.add("INFO " + fmt.Sprintf(format, args...)) }
func (l *testLog) Warnf(format string, args ...any) { l.add("WARN " + fmt.Sprintf(format, args...)) }
func (l *testLog) add(s string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.logs = append(l.logs, s)
}

func (l *testLog) has(substr string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, s := range l.logs {
		if strings.Contains(s, substr) {
			return true
		}
	}
	return false
}

func write(t *testing.T, dir, name, content string) {
	t.Helper()
	require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600), "writing %s", name)
}

func setup(t *testing.T) (*manager, *fakeNSS, string, *testLog) {
	t.Helper()
	dir := t.TempDir()
	fake := newFakeNSS()
	log := &testLog{}
	m := &manager{paths: []string{dir}, home: t.TempDir(), certs: fake.run, log: log}
	return m, fake, dir, log
}

const testInterval = 10 * time.Millisecond

func TestSyncImportsEveryCertificate(t *testing.T) {
	m, fake, dir, _ := setup(t)
	write(t, dir, "one.crt", newCA(t, "one"))
	write(t, dir, "bundle.pem", newCA(t, "two")+newCA(t, "three"))
	write(t, dir, "ignored.txt", newCA(t, "ignored"))
	require.NoError(t, os.Mkdir(filepath.Join(dir, "sub.crt"), 0o700), "creating a directory named like a certificate")

	require.NoError(t, m.reconcile(t.Context()), "syncing")

	assert.Len(t, fake.nicknames(), 3, "every certificate of every .crt/.pem file must be imported, and only those: %v", fake.nicknames())
}

func TestSyncFollowsSymlinks(t *testing.T) {
	// Kubernetes mounts Secret keys as symlinks.
	m, fake, dir, _ := setup(t)
	target := filepath.Join(t.TempDir(), "real")
	write(t, filepath.Dir(target), "real", newCA(t, "linked"))
	require.NoError(t, os.Symlink(target, filepath.Join(dir, "ca.crt")), "creating symlink")

	require.NoError(t, m.reconcile(t.Context()), "syncing")

	assert.Len(t, fake.nicknames(), 1, "a symlinked certificate must be imported")
}

func TestSyncReformattedPEMKeepsCertificate(t *testing.T) {
	m, fake, dir, _ := setup(t)
	ca := newCA(t, "ca")
	write(t, dir, "ca.pem", ca)
	require.NoError(t, m.reconcile(t.Context()), "first sync")
	before := fake.nicknames()
	fake.reset()

	// Same certificate, different line endings, wrapping and surrounding text.
	body := strings.ReplaceAll(strings.TrimSpace(ca), "\n", "\r\n")
	write(t, dir, "ca.pem", "# my corporate CA\r\n"+body+"\r\n\r\n")
	require.NoError(t, m.reconcile(t.Context()), "second sync")

	assert.ElementsMatch(t, before, fake.nicknames(), "a reformatted PEM must keep the same certificate")
	assert.Empty(t, fake.callsWith("-A"), "an unchanged certificate must not be imported again")
	assert.Empty(t, fake.callsWith("-D"), "an unchanged certificate must not be removed")
}

func TestSyncDuplicateCertificateSurvivesRemovingOneCopy(t *testing.T) {
	m, fake, dir, _ := setup(t)
	ca := newCA(t, "ca")
	write(t, dir, "a.pem", ca)
	write(t, dir, "b.pem", strings.ReplaceAll(ca, "\n", "\r\n"))
	require.NoError(t, m.reconcile(t.Context()), "first sync")
	require.Len(t, fake.nicknames(), 1, "two copies of a CA are one certificate")

	require.NoError(t, os.Remove(filepath.Join(dir, "b.pem")), "removing one copy")
	require.NoError(t, m.reconcile(t.Context()), "second sync")

	assert.Len(t, fake.nicknames(), 1, "the CA must stay trusted while one copy remains")
}

func TestSyncRemovesCertificatesNoLongerMounted(t *testing.T) {
	m, fake, dir, _ := setup(t)
	write(t, dir, "keep.pem", newCA(t, "keep"))
	write(t, dir, "drop.pem", newCA(t, "drop"))
	require.NoError(t, m.reconcile(t.Context()), "first sync")
	require.Len(t, fake.nicknames(), 2, "both certificates imported")

	require.NoError(t, os.Remove(filepath.Join(dir, "drop.pem")), "removing a CA")
	require.NoError(t, m.reconcile(t.Context()), "second sync")

	assert.Len(t, fake.nicknames(), 1, "a removed CA must stop being trusted")
}

func TestSyncLeavesOtherCertificatesAlone(t *testing.T) {
	m, fake, dir, _ := setup(t)
	fake.certs["someone-elses-ca"] = true
	write(t, dir, "ca.pem", newCA(t, "ca"))

	require.NoError(t, m.reconcile(t.Context()), "syncing")

	assert.True(t, fake.certs["someone-elses-ca"], "certificates not imported by the agent must not be removed")
}

func TestSyncSkipsInvalidCertificatesWithoutFailing(t *testing.T) {
	m, fake, dir, log := setup(t)
	write(t, dir, "bad.pem", "-----BEGIN CERTIFICATE-----\nbm90IGEgY2VydA==\n-----END CERTIFICATE-----\n")
	write(t, dir, "good.pem", newCA(t, "good"))

	require.NoError(t, m.reconcile(t.Context()), "an invalid certificate can't be fixed by retrying, so it must not fail the sync")

	assert.Len(t, fake.nicknames(), 1, "the valid certificate must still be imported")
	assert.True(t, log.has("invalid certificate"), "the invalid certificate must be reported: %v", log.logs)
}

func TestSyncCorruptDatabaseChangesNothing(t *testing.T) {
	m, fake, dir, _ := setup(t)
	write(t, dir, "ca.pem", newCA(t, "ca"))
	fake.fail = func(op string, _ []string) error {
		if op == "-L" {
			return errors.New("SEC_ERROR_BAD_DATABASE")
		}
		return nil
	}

	err := m.reconcile(t.Context())

	require.Error(t, err, "a corrupt database must be reported")
	assert.Empty(t, fake.callsWith("-A"), "nothing may be imported when the database can't be read")
	assert.Empty(t, fake.callsWith("-D"), "nothing may be removed when the database can't be read")
}

func TestSyncReportsPartialFailure(t *testing.T) {
	m, fake, dir, _ := setup(t)
	write(t, dir, "a.pem", newCA(t, "a"))
	write(t, dir, "b.pem", newCA(t, "b"))
	imports := 0
	fake.fail = func(op string, _ []string) error {
		if op == "-A" {
			imports++
			if imports == 1 {
				return errors.New("disk full")
			}
		}
		return nil
	}

	require.Error(t, m.reconcile(t.Context()), "a failed import must fail the sync")

	assert.Len(t, fake.nicknames(), 1, "the other certificate must still be imported")
}

func TestReconcileImportsConfiguredFilesAndDirectories(t *testing.T) {
	m, fake, dir, _ := setup(t)
	write(t, dir, "in-dir.crt", newCA(t, "in dir"))
	file := filepath.Join(t.TempDir(), "listed.cer")
	require.NoError(t, os.WriteFile(file, []byte(newCA(t, "listed")), 0o600), "writing a listed file")
	m.paths = append(m.paths, file, dir, filepath.Join(t.TempDir(), "missing"))

	require.NoError(t, m.reconcile(t.Context()), "syncing")

	assert.Len(t, fake.nicknames(), 2, "a listed file is read whatever its extension, a directory once, a missing path skipped")
}

func TestReconcileSkipsUnchangedCertificates(t *testing.T) {
	m, fake, dir, _ := setup(t)
	write(t, dir, "ca.crt", newCA(t, "ca"))
	require.NoError(t, m.reconcile(t.Context()), "first sync")
	fake.reset()

	require.NoError(t, m.reconcile(t.Context()), "second sync")

	assert.Empty(t, fake.calls, "certutil must not run while the certificates are unchanged")
}

func TestReconcileTouchesNothingWithoutCertificates(t *testing.T) {
	// On Wolfi the default directory always exists, usually empty: the agent's home
	// must stay as is (the agent owns all of it when it runs as root).
	m, fake, _, _ := setup(t)

	require.NoError(t, m.reconcile(t.Context()), "syncing an empty directory")

	assert.Empty(t, fake.calls, "certutil must not run without certificates to import or remove")
	assert.NoDirExists(t, filepath.Join(m.home, ".pki"), "no database may be created without certificates")
}

func TestRunRetriesAFailedSyncWithoutFileChanges(t *testing.T) {
	m, fake, dir, _ := setup(t)
	write(t, dir, "ca.pem", newCA(t, "ca"))
	var mu sync.Mutex
	broken := true
	fake.fail = func(op string, _ []string) error {
		mu.Lock()
		defer mu.Unlock()
		if broken && op == "-N" {
			return errors.New("read-only file system")
		}
		return nil
	}
	require.Error(t, m.reconcile(t.Context()), "the first sync must fail")

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go m.run(ctx, testInterval)
	time.Sleep(50 * time.Millisecond)
	require.Empty(t, fake.nicknames(), "nothing is imported while the database can't be created")

	mu.Lock()
	broken = false
	mu.Unlock()

	assert.Eventually(t, func() bool { return len(fake.nicknames()) == 1 }, 5*time.Second, 10*time.Millisecond,
		"the failed change must be retried without the files changing")
}

func TestRunAppliesChangesWhileRunning(t *testing.T) {
	m, fake, dir, _ := setup(t)
	require.NoError(t, m.reconcile(t.Context()), "starting with no CA")
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go m.run(ctx, testInterval)

	write(t, dir, "ca.crt", newCA(t, "ca"))
	assert.Eventually(t, func() bool { return len(fake.nicknames()) == 1 }, 5*time.Second, 10*time.Millisecond,
		"a CA mounted while running must be imported")

	require.NoError(t, os.Remove(filepath.Join(dir, "ca.crt")), "removing the CA")
	assert.Eventually(t, func() bool { return len(fake.nicknames()) == 0 }, 5*time.Second, 10*time.Millisecond,
		"a CA removed while running must stop being trusted")
}

func TestRunStopsWithItsContext(t *testing.T) {
	m, _, _, _ := setup(t)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { m.run(ctx, testInterval); close(done) }()

	cancel()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		require.Fail(t, "run must return once its context is done")
	}
}

func TestSyncChownsTheDatabase(t *testing.T) {
	// Chowning to oneself works without root and proves the call is made.
	m, _, dir, _ := setup(t)
	m.owner = &owner{uid: os.Getuid(), gid: os.Getgid()}
	write(t, dir, "ca.pem", newCA(t, "ca"))

	require.NoError(t, m.reconcile(t.Context()), "syncing as the database owner")

	assert.DirExists(t, filepath.Join(m.home, ".pki", "nssdb"), "database directory")
}

func TestBrowserHome(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("covers a browser that runs as the agent's own, non-root user")
	}
	cur, err := user.Current()
	require.NoError(t, err, "current user")

	t.Run("a writable HOME is used as is", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("HOME", home)
		t.Setenv(browserUserEnv, cur.Username)

		got, o := browserHome(&testLog{})

		assert.Equal(t, home, got, "browser home")
		assert.Nil(t, o, "only root changes the owner")
		assert.Equal(t, home, os.Getenv("HOME"), "HOME must not change")
	})

	t.Run("a read-only HOME falls back to the browser user's home", func(t *testing.T) {
		t.Setenv("HOME", "/proc")
		t.Setenv(browserUserEnv, cur.Username)

		got, o := browserHome(&testLog{})

		assert.Equal(t, cur.HomeDir, got, "browser home")
		assert.Nil(t, o, "only root changes the owner")
		assert.Equal(t, cur.HomeDir, os.Getenv("HOME"), "HOME must be exported for the browser")
	})

	t.Run("without a browser user a read-only HOME is kept", func(t *testing.T) {
		t.Setenv("HOME", "/proc")
		t.Setenv(browserUserEnv, "")

		got, _ := browserHome(&testLog{})

		assert.Equal(t, "/proc", got, "browser home")
	})
}

func TestStartDoesNothingWithoutTheConfiguredPaths(t *testing.T) {
	log, logs := loggertest.New(t.Name())
	Start(t.Context(), log, Config{CertificateAuthorities: []string{filepath.Join(t.TempDir(), "missing")}})
	assert.Zero(t, logs.Len(), "nothing may be logged or done when no configured path exists")
}

func TestLookupBrowserUser(t *testing.T) {
	cur, err := user.Current()
	require.NoError(t, err, "current user")

	home, o, err := lookupBrowserUser(cur.Username)
	require.NoError(t, err, "looking up an existing user")
	assert.Equal(t, cur.HomeDir, home, "the browser's home is the user's home")
	assert.Equal(t, &owner{uid: os.Getuid(), gid: os.Getgid()}, o, "owner")

	home, o, err = lookupBrowserUser("")
	require.NoError(t, err, "no configured user is not an error")
	assert.Empty(t, home, "no home when no user is configured")
	assert.Nil(t, o, "no owner when no user is configured")

	_, _, err = lookupBrowserUser("no-such-user-for-customca")
	assert.Error(t, err, "an unknown user must be reported")
}
