// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package release

import (
	"os"
	"testing"
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
			got, err := inferLatestRelease(tt.version)
			if (err != nil) != tt.wantErr {
				t.Errorf("inferLatestRelease() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("inferLatestRelease() = %v, want %v", got, tt.want)
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
			got, err := inferNextRelease(tt.version)
			if (err != nil) != tt.wantErr {
				t.Errorf("inferNextRelease() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("inferNextRelease() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestLoadConfigFromEnv(t *testing.T) {
	originalVars := map[string]string{
		"CURRENT_RELEASE": os.Getenv("CURRENT_RELEASE"),
		"BASE_BRANCH":     os.Getenv("BASE_BRANCH"),
		"PROJECT_OWNER":   os.Getenv("PROJECT_OWNER"),
		"PROJECT_REPO":    os.Getenv("PROJECT_REPO"),
		"DRY_RUN":         os.Getenv("DRY_RUN"),
	}
	t.Cleanup(func() {
		for key, val := range originalVars {
			if val == "" {
				os.Unsetenv(key)
			} else {
				os.Setenv(key, val)
			}
		}
	})

	os.Unsetenv("CURRENT_RELEASE")
	os.Unsetenv("BASE_BRANCH")
	os.Unsetenv("PROJECT_OWNER")
	os.Unsetenv("PROJECT_REPO")
	os.Unsetenv("DRY_RUN")

	os.Setenv("CURRENT_RELEASE", "9.5.0")

	cfg, err := LoadConfigFromEnv()
	if err != nil {
		t.Fatalf("LoadConfigFromEnv() error = %v", err)
	}

	if cfg.CurrentRelease != "9.5.0" {
		t.Errorf("CurrentRelease = %s, want 9.5.0", cfg.CurrentRelease)
	}
	if cfg.ReleaseBranch != "9.5" {
		t.Errorf("ReleaseBranch = %s, want 9.5", cfg.ReleaseBranch)
	}
	if cfg.NextRelease != "9.5.1" {
		t.Errorf("NextRelease = %s, want 9.5.1", cfg.NextRelease)
	}
	if cfg.BaseBranch != "main" {
		t.Errorf("BaseBranch = %s, want main", cfg.BaseBranch)
	}
	if cfg.ProjectOwner != "elastic" {
		t.Errorf("ProjectOwner = %s, want elastic", cfg.ProjectOwner)
	}
	if cfg.ProjectRepo != "elastic-agent" {
		t.Errorf("ProjectRepo = %s, want elastic-agent", cfg.ProjectRepo)
	}
}
