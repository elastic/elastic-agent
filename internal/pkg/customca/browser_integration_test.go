// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration && linux

package customca

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These tests need a browser that trusts what the manager imports, so they run in
// an elastic-agent-complete image (certutil, elastic-synthetics and Chromium, with
// ELASTIC_SYNTHETICS_CAPABLE=true). Run the compiled test binary there, once as a
// regular user and once as root:
//
//	go test -c -tags integration -o customca.test ./internal/pkg/customca
//	docker run --rm -u 1000 -v $PWD/customca.test:/t:ro --entrypoint /t IMAGE -test.run Browser -test.v
//	docker run --rm -u 0    -v $PWD/customca.test:/t:ro --entrypoint /t IMAGE -test.run Browser -test.v

const journeyTimeout = 90 * time.Second

// serveTLS starts an HTTPS server on 127.0.0.1 whose certificate a returned CA signed,
// and returns the server URL and the CA in PEM form.
func serveTLS(t *testing.T) (url, caPEM string) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err, "generating CA key")
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "customca integration test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	require.NoError(t, err, "creating CA")
	caCert, err := x509.ParseCertificate(caDER)
	require.NoError(t, err, "parsing CA")

	srvKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err, "generating server key")
	srvDER, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}, caCert, &srvKey.PublicKey, caKey)
	require.NoError(t, err, "creating server certificate")

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("<html><title>ok</title></html>"))
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{srvDER}, PrivateKey: srvKey}}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv.URL, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}))
}

// browserUser is who runs the browser: the current user, or when root, the beat user,
// as Heartbeat does with BEAT_SETUID_AS.
type browserUser struct {
	home string
	cred *syscall.Credential
}

func newBrowserUser(t *testing.T) (browserUser, *Owner) {
	t.Helper()
	home, err := os.MkdirTemp("", "customca-home-")
	require.NoError(t, err, "creating the browser's home")
	t.Cleanup(func() { _ = os.RemoveAll(home) })
	require.NoError(t, os.Chmod(home, 0o755), "making the home traversable")
	if os.Geteuid() != 0 {
		return browserUser{home: home}, nil
	}
	name := os.Getenv(BrowserUserEnv)
	if name == "" {
		name = "elastic-agent"
	}
	u, err := user.Lookup(name)
	require.NoError(t, err, "looking up the browser user %q", name)
	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)
	require.NoError(t, os.Chown(home, uid, gid), "giving the home to the browser user")
	return browserUser{home: home, cred: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)}}, &Owner{UID: uid, GID: gid}
}

// journeyStatus runs a one-step journey that opens url in Chromium and returns its
// status ("succeeded" or "failed") and the output of the run.
func journeyStatus(ctx context.Context, t *testing.T, u browserUser, url string) (string, string) {
	t.Helper()
	cmd := exec.CommandContext(ctx, "elastic-synthetics", "--inline", "--reporter", "json", "--no-throttling")
	cmd.Dir = u.home
	cmd.Stdin = strings.NewReader(`step("load", async () => { await page.goto("` + url + `"); });`)
	browsers := os.Getenv("PLAYWRIGHT_BROWSERS_PATH")
	if browsers == "" {
		browsers = "/usr/share/elastic-agent/.cache/ms-playwright"
	}
	cmd.Env = append(os.Environ(), "HOME="+u.home, "PLAYWRIGHT_BROWSERS_PATH="+browsers, "XDG_CACHE_HOME="+filepath.Join(u.home, ".cache"))
	if u.cred != nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: u.cred}
	}
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	_ = cmd.Run() // a failed journey exits non-zero; the status is in the output

	for _, line := range strings.Split(out.String(), "\n") {
		var ev struct {
			Type    string `json:"type"`
			Journey struct {
				Status string `json:"status"`
			} `json:"journey"`
		}
		if json.Unmarshal([]byte(line), &ev) == nil && ev.Type == "journey/end" {
			return ev.Journey.Status, out.String()
		}
	}
	return "", out.String()
}

func TestBrowserTrustsMountedCA(t *testing.T) {
	if os.Getenv("ELASTIC_SYNTHETICS_CAPABLE") != "true" {
		t.Skip("needs the elastic-agent-complete image (ELASTIC_SYNTHETICS_CAPABLE=true)")
	}
	certutil, err := exec.LookPath("certutil")
	require.NoError(t, err, "certutil must be installed in the complete image")
	_, err = exec.LookPath("elastic-synthetics")
	require.NoError(t, err, "elastic-synthetics must be installed in the complete image")

	url, caPEM := serveTLS(t)
	u, owner := newBrowserUser(t)
	dir := t.TempDir()
	require.NoError(t, os.Chmod(dir, 0o755), "making the CA directory readable")

	m := New(Config{Dir: dir, Home: u.home, Interval: 200 * time.Millisecond, Runner: ExecRunner(certutil), Owner: owner})
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Minute)
	defer cancel()
	go m.Run(ctx)

	status := func() string {
		jctx, jcancel := context.WithTimeout(ctx, journeyTimeout)
		defer jcancel()
		s, _ := journeyStatus(jctx, t, u, url)
		return s
	}
	var lastOutput string
	waitFor := func(want string) bool {
		return assert.Eventually(t, func() bool {
			jctx, jcancel := context.WithTimeout(ctx, journeyTimeout)
			defer jcancel()
			s, out := journeyStatus(jctx, t, u, url)
			lastOutput = out
			return s == want
		}, 2*time.Minute, 500*time.Millisecond, "the browser run must end %q; last output:\n%s", want, lastOutput)
	}

	require.Equal(t, "failed", status(), "without the CA the browser must reject the server's certificate, or this test proves nothing")

	require.NoError(t, os.WriteFile(filepath.Join(dir, "ca.crt"), []byte(caPEM), 0o644), "mounting the CA")
	require.True(t, waitFor("succeeded"), "a CA mounted while running must be trusted by the browser, without a restart")

	require.NoError(t, os.Remove(filepath.Join(dir, "ca.crt")), "unmounting the CA")
	require.True(t, waitFor("failed"), "a CA removed while running must stop being trusted by the browser")
}
