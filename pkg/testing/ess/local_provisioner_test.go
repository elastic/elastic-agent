// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package ess

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

// testLogger adapts *testing.T to common.Logger.
type testLogger struct{ t *testing.T }

func (l testLogger) Logf(format string, args ...any) { l.t.Logf(format, args...) }

func TestParseShellinit(t *testing.T) {
	// Mirrors `elastic-package stack shellinit --shell bash` output (POSIX `export`
	// lines), with some noise that must be ignored and a quoted value.
	out := `2026/05/29 18:00:00  WARN CommitHash is undefined
export ELASTIC_PACKAGE_ELASTICSEARCH_API_KEY=abc123
export ELASTIC_PACKAGE_ELASTICSEARCH_HOST=https://127.0.0.1:9200
export ELASTIC_PACKAGE_ELASTICSEARCH_USERNAME=elastic
export ELASTIC_PACKAGE_ELASTICSEARCH_PASSWORD="changeme"
export ELASTIC_PACKAGE_KIBANA_HOST=https://127.0.0.1:5601
export ELASTIC_PACKAGE_CA_CERT=/home/u/.elastic-package/profiles/p/certs/ca-cert.pem

garbage line without equals
`
	got := parseShellinit(out)

	want := map[string]string{
		epElasticsearchUsernameEnv: "elastic",
		epElasticsearchPasswordEnv: "changeme",
		epCACertEnv:                "/home/u/.elastic-package/profiles/p/certs/ca-cert.pem",
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("parseShellinit()[%q] = %q, want %q", k, got[k], v)
		}
	}
	// The WARN line and the no-equals line must not produce entries.
	if _, ok := got["garbage line without equals"]; ok {
		t.Errorf("parseShellinit kept a line without an equals sign")
	}
	if v := got["ELASTIC_PACKAGE_KIBANA_HOST"]; v != "https://127.0.0.1:5601" {
		t.Errorf("kibana host = %q, want https://127.0.0.1:5601", v)
	}
}

func TestNetworkName(t *testing.T) {
	cases := []struct {
		profile string
		want    string
	}{
		{"default", "elastic-package-stack_default"},
		{"", "elastic-package-stack_default"},
		{"elastic-agent-integration", "elastic-package-stack-elastic-agent-integration_default"},
	}
	for _, c := range cases {
		p := &LocalProvisioner{profile: c.profile}
		if got := p.networkName(); got != c.want {
			t.Errorf("networkName(profile=%q) = %q, want %q", c.profile, got, c.want)
		}
	}
}

func TestNewLocalProvisioner(t *testing.T) {
	t.Run("bin and profile from env", func(t *testing.T) {
		t.Setenv("ELASTIC_PACKAGE_BIN", "/usr/bin/true")
		t.Setenv("ELASTIC_PACKAGE_PROFILE", "custom-profile")
		sp, err := NewLocalProvisioner()
		if err != nil {
			t.Fatalf("NewLocalProvisioner() error = %v", err)
		}
		p := sp.(*LocalProvisioner)
		if p.bin != "/usr/bin/true" {
			t.Errorf("bin = %q, want /usr/bin/true", p.bin)
		}
		if p.profile != "custom-profile" {
			t.Errorf("profile = %q, want custom-profile", p.profile)
		}
		if sp.Name() != ProvisionerLocal {
			t.Errorf("Name() = %q, want %q", sp.Name(), ProvisionerLocal)
		}
	})

	t.Run("default profile", func(t *testing.T) {
		t.Setenv("ELASTIC_PACKAGE_BIN", "/usr/bin/true")
		t.Setenv("ELASTIC_PACKAGE_PROFILE", "")
		sp, err := NewLocalProvisioner()
		if err != nil {
			t.Fatalf("NewLocalProvisioner() error = %v", err)
		}
		if sp.(*LocalProvisioner).profile != localDefaultProfile {
			t.Errorf("profile = %q, want %q", sp.(*LocalProvisioner).profile, localDefaultProfile)
		}
	})

	t.Run("missing binary errors", func(t *testing.T) {
		t.Setenv("ELASTIC_PACKAGE_BIN", "")
		t.Setenv("PATH", t.TempDir()) // empty dir: elastic-package not findable
		if _, err := NewLocalProvisioner(); err == nil {
			t.Error("NewLocalProvisioner() expected an error when the binary is missing")
		}
	})
}

func TestCommandUsesProfileEnvNotFlag(t *testing.T) {
	p := &LocalProvisioner{bin: "/usr/bin/true", profile: "myprofile"}
	cmd := p.command(context.Background(), "stack", "status")

	// The profile must be passed via the environment, never as a -p/--profile flag
	// (which is not accepted by every subcommand, e.g. `profiles create`).
	wantArgs := []string{"/usr/bin/true", "stack", "status"}
	if !slices.Equal(cmd.Args, wantArgs) {
		t.Errorf("cmd.Args = %v, want %v", cmd.Args, wantArgs)
	}
	if slices.Contains(cmd.Args, "-p") || slices.Contains(cmd.Args, "--profile") {
		t.Errorf("cmd.Args unexpectedly contains a profile flag: %v", cmd.Args)
	}
	if !slices.Contains(cmd.Env, epProfileEnv+"=myprofile") {
		t.Errorf("cmd.Env missing %s=myprofile; got %v", epProfileEnv, cmd.Env)
	}
}

func TestReadCACert(t *testing.T) {
	t.Run("reads contents", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "ca-cert.pem")
		content := "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		got, err := readCACert(path)
		if err != nil {
			t.Fatalf("readCACert() error = %v", err)
		}
		if got != content {
			t.Errorf("readCACert() = %q, want %q", got, content)
		}
	})

	t.Run("empty path errors", func(t *testing.T) {
		if _, err := readCACert(""); err == nil {
			t.Error("readCACert(\"\") expected an error")
		}
	})

	t.Run("missing file errors", func(t *testing.T) {
		if _, err := readCACert(filepath.Join(t.TempDir(), "nope.pem")); err == nil {
			t.Error("readCACert(missing) expected an error")
		}
	})
}

func TestApplyLocalClusterSettings(t *testing.T) {
	t.Run("sends PUT with auth and body", func(t *testing.T) {
		var gotMethod, gotPath, gotBody, gotUser, gotPass string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotMethod = r.Method
			gotPath = r.URL.Path
			b, _ := io.ReadAll(r.Body)
			gotBody = string(b)
			gotUser, gotPass, _ = r.BasicAuth()
			w.WriteHeader(http.StatusOK)
		}))
		defer srv.Close()

		// Trailing slash on the URL must not produce a double slash in the path.
		if err := applyLocalClusterSettings(context.Background(), srv.URL+"/", "elastic", "secret", ""); err != nil {
			t.Fatalf("applyLocalClusterSettings() error = %v", err)
		}
		if gotMethod != http.MethodPut {
			t.Errorf("method = %q, want PUT", gotMethod)
		}
		if gotPath != "/_cluster/settings" {
			t.Errorf("path = %q, want /_cluster/settings", gotPath)
		}
		if gotBody != localClusterSettings {
			t.Errorf("body = %q, want %q", gotBody, localClusterSettings)
		}
		if gotUser != "elastic" || gotPass != "secret" {
			t.Errorf("basic auth = %q:%q, want elastic:secret", gotUser, gotPass)
		}
	})

	t.Run("non-2xx is an error", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "boom", http.StatusInternalServerError)
		}))
		defer srv.Close()
		if err := applyLocalClusterSettings(context.Background(), srv.URL, "u", "p", ""); err == nil {
			t.Error("applyLocalClusterSettings() expected an error on 500")
		}
	})
}

// TestEnsureProfileWithBinary exercises ensureProfile against the real
// elastic-package binary when it is available, in an isolated data directory so it
// does not touch the developer's real ~/.elastic-package. It is skipped when the
// binary is not installed.
func TestEnsureProfileWithBinary(t *testing.T) {
	bin := os.Getenv("ELASTIC_PACKAGE_BIN")
	if bin == "" {
		found, err := exec.LookPath("elastic-package")
		if err != nil {
			t.Skip("elastic-package binary not available; skipping binary-backed test")
		}
		bin = found
	}

	// Isolate elastic-package's data directory for this test so it does not touch
	// the developer's real ~/.elastic-package. The path is used as-is as the root
	// dir, and elastic-package treats an existing dir as "already installed" and
	// skips bootstrapping it; so point at a not-yet-created subdir and let
	// elastic-package's own EnsureInstalled (run on every invocation) create it.
	t.Setenv("ELASTIC_PACKAGE_DATA_HOME", filepath.Join(t.TempDir(), "ep-home"))

	p := &LocalProvisioner{bin: bin, profile: "eat-local-provisioner-test"}
	p.SetLogger(testLogger{t})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	if err := p.ensureProfile(ctx); err != nil {
		t.Fatalf("ensureProfile() first call error = %v", err)
	}
	// Second call must be a no-op (profile already exists), not an error.
	if err := p.ensureProfile(ctx); err != nil {
		t.Fatalf("ensureProfile() second call (idempotency) error = %v", err)
	}
}
