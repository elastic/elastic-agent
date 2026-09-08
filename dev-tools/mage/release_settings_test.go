// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package mage

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestInferLatestRelease(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    string
		wantErr bool
	}{
		{
			name:    "valid version",
			version: "9.2.1",
			want:    "9.2.0",
			wantErr: false,
		},
		{
			name:    "patch version is 0",
			version: "9.2.0",
			want:    "",
			wantErr: false,
		},
		{
			name:    "invalid format",
			version: "9.2",
			want:    "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed, err := ParseReleaseVersion(tt.version)
			if tt.wantErr {
				if err == nil {
					t.Errorf("ParseReleaseVersion() error = nil, wantErr %v", tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Errorf("ParseReleaseVersion() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			got := InferLatestRelease(parsed)
			if got != tt.want {
				t.Errorf("InferLatestRelease() = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestInferNextRelease(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    string
		wantErr bool
	}{
		{
			name:    "valid version",
			version: "9.2.0",
			want:    "9.2.1",
			wantErr: false,
		},
		{
			name:    "invalid format",
			version: "9.2",
			want:    "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed, err := ParseReleaseVersion(tt.version)
			if tt.wantErr {
				if err == nil {
					t.Errorf("ParseReleaseVersion() error = nil, wantErr %v", tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Errorf("ParseReleaseVersion() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			got := InferNextRelease(parsed)
			if got != tt.want {
				t.Errorf("InferNextRelease() = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestLoadReleaseSettingsFromEnv(t *testing.T) {
	keys := []string{
		"CURRENT_RELEASE",
		"BASE_BRANCH",
		"PROJECT_OWNER",
		"PROJECT_REPO",
		"DRY_RUN",
		"PROJECT_REVIEWERS",
		"GITHUB_TOKEN",
		"GIT_AUTHOR_NAME",
		"GIT_AUTHOR_EMAIL",
	}
	original := make(map[string]string, len(keys))
	for _, key := range keys {
		original[key] = os.Getenv(key)
		os.Unsetenv(key)
	}
	t.Cleanup(func() {
		for key, val := range original {
			if val == "" {
				os.Unsetenv(key)
			} else {
				os.Setenv(key, val)
			}
		}
	})

	os.Setenv("CURRENT_RELEASE", "9.5.0")

	s := DefaultSettings()
	require.NoError(t, s.loadReleaseSettingsFromEnv())

	if s.Release.CurrentRelease != "9.5.0" {
		t.Errorf("CurrentRelease = %s, want 9.5.0", s.Release.CurrentRelease)
	}
	if s.Release.ReleaseBranch != "9.5" {
		t.Errorf("ReleaseBranch = %s, want 9.5", s.Release.ReleaseBranch)
	}
	if s.Release.NextRelease != "9.5.1" {
		t.Errorf("NextRelease = %s, want 9.5.1", s.Release.NextRelease)
	}
	if s.Release.BaseBranch != "main" {
		t.Errorf("BaseBranch = %s, want main", s.Release.BaseBranch)
	}
	if s.Release.ProjectOwner != "elastic" {
		t.Errorf("ProjectOwner = %s, want elastic", s.Release.ProjectOwner)
	}
	if s.Release.ProjectRepo != "elastic-agent" {
		t.Errorf("ProjectRepo = %s, want elastic-agent", s.Release.ProjectRepo)
	}
	if s.Release.NextProjectMinorVersion != "9.6.0" {
		t.Errorf("NextProjectMinorVersion = %s, want 9.6.0", s.Release.NextProjectMinorVersion)
	}
	if s.Release.NextProjectMinorBranch != "9.6" {
		t.Errorf("NextProjectMinorBranch = %s, want 9.6", s.Release.NextProjectMinorBranch)
	}
	require.NoError(t, s.RequireRelease())
}

func TestRequireReleaseMissingCurrent(t *testing.T) {
	s := DefaultSettings()
	if err := s.RequireRelease(); err == nil {
		t.Fatal("RequireRelease() expected error when CURRENT_RELEASE is unset")
	}
}
