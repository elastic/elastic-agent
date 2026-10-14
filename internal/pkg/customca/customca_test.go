// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

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

func (f *fakeNSS) run(_ context.Context, args ...string) ([]byte, error) {
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
		data, err := os.ReadFile(arg("-i"))
		if err != nil {
			return nil, err
		}
		if block, _ := pem.Decode(data); block == nil || block.Type != "CERTIFICATE" {
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

func setup(t *testing.T) (*Manager, *fakeNSS, string, *testLog) {
	t.Helper()
	dir := t.TempDir()
	fake := newFakeNSS()
	log := &testLog{}
	m := New(Config{Dir: dir, Home: t.TempDir(), Interval: 10 * time.Millisecond, Runner: fake.run, Log: log})
	return m, fake, dir, log
}

func TestSyncImportsEveryCertificate(t *testing.T) {
	m, fake, dir, _ := setup(t)
	write(t, dir, "one.crt", newCA(t, "one"))
	write(t, dir, "bundle.pem", newCA(t, "two")+newCA(t, "three"))
	write(t, dir, "ignored.txt", newCA(t, "ignored"))
	require.NoError(t, os.Mkdir(filepath.Join(dir, "sub.crt"), 0o700), "creating a directory named like a certificate")

	require.NoError(t, m.Sync(t.Context()), "syncing")

	assert.Len(t, fake.nicknames(), 3, "every certificate of every .crt/.pem file must be imported, and only those: %v", fake.nicknames())
}

func TestSyncFollowsSymlinks(t *testing.T) {
	// Kubernetes mounts Secret keys as symlinks.
	m, fake, dir, _ := setup(t)
	target := filepath.Join(t.TempDir(), "real")
	write(t, filepath.Dir(target), "real", newCA(t, "linked"))
	require.NoError(t, os.Symlink(target, filepath.Join(dir, "ca.crt")), "creating symlink")

	require.NoError(t, m.Sync(t.Context()), "syncing")

	assert.Len(t, fake.nicknames(), 1, "a symlinked certificate must be imported")
}

func TestSyncReformattedPEMKeepsCertificate(t *testing.T) {
	m, fake, dir, _ := setup(t)
	ca := newCA(t, "ca")
	write(t, dir, "ca.pem", ca)
	require.NoError(t, m.Sync(t.Context()), "first sync")
	before := fake.nicknames()
	fake.reset()

	// Same certificate, different line endings, wrapping and surrounding text.
	body := strings.ReplaceAll(strings.TrimSpace(ca), "\n", "\r\n")
	write(t, dir, "ca.pem", "# my corporate CA\r\n"+body+"\r\n\r\n")
	require.NoError(t, m.Sync(t.Context()), "second sync")

	assert.ElementsMatch(t, before, fake.nicknames(), "a reformatted PEM must keep the same certificate")
	assert.Empty(t, fake.callsWith("-A"), "an unchanged certificate must not be imported again")
	assert.Empty(t, fake.callsWith("-D"), "an unchanged certificate must not be removed")
}

func TestSyncDuplicateCertificateSurvivesRemovingOneCopy(t *testing.T) {
	m, fake, dir, _ := setup(t)
	ca := newCA(t, "ca")
	write(t, dir, "a.pem", ca)
	write(t, dir, "b.pem", strings.ReplaceAll(ca, "\n", "\r\n"))
	require.NoError(t, m.Sync(t.Context()), "first sync")
	require.Len(t, fake.nicknames(), 1, "two copies of a CA are one certificate")

	require.NoError(t, os.Remove(filepath.Join(dir, "b.pem")), "removing one copy")
	require.NoError(t, m.Sync(t.Context()), "second sync")

	assert.Len(t, fake.nicknames(), 1, "the CA must stay trusted while one copy remains")
}

func TestSyncRemovesCertificatesNoLongerMounted(t *testing.T) {
	m, fake, dir, _ := setup(t)
	write(t, dir, "keep.pem", newCA(t, "keep"))
	write(t, dir, "drop.pem", newCA(t, "drop"))
	require.NoError(t, m.Sync(t.Context()), "first sync")
	require.Len(t, fake.nicknames(), 2, "both certificates imported")

	require.NoError(t, os.Remove(filepath.Join(dir, "drop.pem")), "removing a CA")
	require.NoError(t, m.Sync(t.Context()), "second sync")

	assert.Len(t, fake.nicknames(), 1, "a removed CA must stop being trusted")
}

func TestSyncLeavesOtherCertificatesAlone(t *testing.T) {
	m, fake, dir, _ := setup(t)
	fake.certs["someone-elses-ca"] = true
	write(t, dir, "ca.pem", newCA(t, "ca"))

	require.NoError(t, m.Sync(t.Context()), "syncing")

	assert.True(t, fake.certs["someone-elses-ca"], "certificates not imported by the agent must not be removed")
}

func TestSyncSkipsInvalidCertificatesWithoutFailing(t *testing.T) {
	m, fake, dir, log := setup(t)
	write(t, dir, "bad.pem", "-----BEGIN CERTIFICATE-----\nbm90IGEgY2VydA==\n-----END CERTIFICATE-----\n")
	write(t, dir, "good.pem", newCA(t, "good"))

	require.NoError(t, m.Sync(t.Context()), "an invalid certificate can't be fixed by retrying, so it must not fail the sync")

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

	err := m.Sync(t.Context())

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

	require.Error(t, m.Sync(t.Context()), "a failed import must fail the sync")

	assert.Len(t, fake.nicknames(), 1, "the other certificate must still be imported")
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
	require.Error(t, m.Sync(t.Context()), "the first sync must fail")

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go m.Run(ctx)
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
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go m.Run(ctx)

	time.Sleep(50 * time.Millisecond)
	assert.Empty(t, fake.callsWith("-L"), "nothing to do while no CA was ever mounted: the database must not even be created")

	ca := newCA(t, "ca")
	write(t, dir, "ca.crt", ca)
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
	go func() { m.Run(ctx); close(done) }()

	cancel()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		require.Fail(t, "Run must return once its context is done")
	}
}

func TestSyncChownsTheDatabase(t *testing.T) {
	// Chowning to oneself works without root and proves the call is made.
	m, _, dir, _ := setup(t)
	m.cfg.Owner = &Owner{UID: os.Getuid(), GID: os.Getgid()}
	write(t, dir, "ca.pem", newCA(t, "ca"))

	require.NoError(t, m.Sync(t.Context()), "syncing as the database owner")

	assert.DirExists(t, filepath.Join(m.cfg.Home, ".pki", "nssdb"), "database directory")
}

func TestBrowserHome(t *testing.T) {
	writableHome := t.TempDir()
	tests := []struct {
		name        string
		isRoot      bool
		home        string
		wantHome    string
		wantSetHome bool
	}{
		{"root uses the browser user's home and leaves HOME alone", true, "/root", "/beat", false},
		{"a writable HOME is used", false, writableHome, writableHome, false},
		{"a read-only HOME falls back to the agent home", false, "/proc", "/beat", true},
		{"a missing HOME falls back to the agent home", false, "", "/beat", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			home, set := BrowserHome(tc.isRoot, tc.home, "/beat")
			assert.Equal(t, tc.wantHome, home, "home directory")
			assert.Equal(t, tc.wantSetHome, set, "whether HOME must be changed")
		})
	}
}

func TestParseInterval(t *testing.T) {
	tests := map[string]time.Duration{
		"":         DefaultInterval,
		"5":        5 * time.Second,
		"0":        0,
		"2m":       2 * time.Minute,
		"500ms":    500 * time.Millisecond,
		"nonsense": DefaultInterval,
		"-3":       DefaultInterval,
	}
	for in, want := range tests {
		assert.Equal(t, want, ParseInterval(in), "ParseInterval(%q)", in)
	}
}

func TestStartDoesNothingWithoutTheDirectory(t *testing.T) {
	log := &testLog{}
	Start(t.Context(), Options{Dir: filepath.Join(t.TempDir(), "missing"), BeatHome: t.TempDir(), Log: log})
	assert.Empty(t, log.logs, "nothing may be logged or done when no CA directory is mounted")
}

func TestLookupBrowserUser(t *testing.T) {
	cur, err := user.Current()
	require.NoError(t, err, "current user")

	u, owner, err := lookupBrowserUser(cur.Username)
	require.NoError(t, err, "looking up an existing user")
	assert.Equal(t, cur.HomeDir, u.HomeDir, "the browser's home is the user's home")
	assert.Equal(t, os.Getuid(), owner.UID, "owner UID")
	assert.Equal(t, os.Getgid(), owner.GID, "owner GID")

	u, owner, err = lookupBrowserUser("")
	require.NoError(t, err, "no configured user is not an error")
	assert.Nil(t, u, "no user when none is configured")
	assert.Nil(t, owner, "no owner when none is configured")

	_, _, err = lookupBrowserUser("no-such-user-for-customca")
	assert.Error(t, err, "an unknown user must be reported")
}
