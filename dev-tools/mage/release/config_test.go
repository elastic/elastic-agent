// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package release

import (
	"testing"
)

func TestValidateReleaseConfig(t *testing.T) {
	t.Run("requires current release", func(t *testing.T) {
		err := ValidateReleaseConfig(&ReleaseConfig{DryRun: true})
		if err == nil {
			t.Fatal("expected error for empty CurrentRelease")
		}
	})

	t.Run("requires token when not dry-run", func(t *testing.T) {
		err := ValidateReleaseConfig(&ReleaseConfig{CurrentRelease: "9.5.0"})
		if err == nil {
			t.Fatal("expected error for missing GITHUB_TOKEN")
		}
	})

	t.Run("ok in dry-run without token", func(t *testing.T) {
		err := ValidateReleaseConfig(&ReleaseConfig{CurrentRelease: "9.5.0", DryRun: true})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

func TestEnsureLatestRelease(t *testing.T) {
	orig := fetchLatestReleaseBefore
	fetchLatestReleaseBefore = func(token, owner, repo, current string) (string, error) {
		return "9.4.2", nil
	}
	t.Cleanup(func() { fetchLatestReleaseBefore = orig })

	cfg := &ReleaseConfig{CurrentRelease: "9.5.0"}
	if err := EnsureLatestRelease(cfg); err != nil {
		t.Fatalf("EnsureLatestRelease() error = %v", err)
	}
	if cfg.LatestRelease != "9.4.2" {
		t.Fatalf("LatestRelease = %s, want 9.4.2", cfg.LatestRelease)
	}

	cfg.LatestRelease = "already-set"
	if err := EnsureLatestRelease(cfg); err != nil {
		t.Fatalf("EnsureLatestRelease() error = %v", err)
	}
	if cfg.LatestRelease != "already-set" {
		t.Fatalf("LatestRelease = %s, want already-set", cfg.LatestRelease)
	}
}
