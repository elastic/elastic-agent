// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package release

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
	"gopkg.in/yaml.v3"
)

func TestUpdateVersion(t *testing.T) {
	// Create a temporary directory for test files
	tmpDir := t.TempDir()
	versionDir := filepath.Join(tmpDir, "version")
	err := os.Mkdir(versionDir, 0755)
	if err != nil {
		t.Fatalf("failed to create version dir: %v", err)
	}

	versionFile := filepath.Join(versionDir, "version.go")
	initialContent := `// Copyright notice

package version

const defaultBeatVersion = "9.4.0"
const Agent = defaultBeatVersion
`
	err = os.WriteFile(versionFile, []byte(initialContent), 0644)
	if err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	// Change to temp directory
	originalWd, _ := os.Getwd()
	defer func() {
		if err := os.Chdir(originalWd); err != nil {
			t.Logf("failed to restore working directory: %v", err)
		}
	}()
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatalf("failed to change to temp directory: %v", err)
	}

	tests := []struct {
		name        string
		newVersion  string
		wantVersion string
		wantError   bool
	}{
		{
			name:        "update to new version",
			newVersion:  "9.5.0",
			wantVersion: `"9.5.0"`,
			wantError:   false,
		},
		{
			name:        "update to major version",
			newVersion:  "10.0.0",
			wantVersion: `"10.0.0"`,
			wantError:   false,
		},
		{
			name:        "update to patch version",
			newVersion:  "9.4.1",
			wantVersion: `"9.4.1"`,
			wantError:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := UpdateVersion(tt.newVersion)
			if (err != nil) != tt.wantError {
				t.Errorf("UpdateVersion() error = %v, wantError %v", err, tt.wantError)
				return
			}

			if !tt.wantError {
				content, err := os.ReadFile(versionFile)
				if err != nil {
					t.Fatalf("failed to read version file: %v", err)
				}

				if !strings.Contains(string(content), tt.wantVersion) {
					t.Errorf("UpdateVersion() content = %v, want to contain %v", string(content), tt.wantVersion)
				}
			}
		})
	}
}

func TestUpdateDocs(t *testing.T) {
	// Create a temporary directory for test files
	tmpDir := t.TempDir()

	// Create deploy/kubernetes directory
	k8sDir := filepath.Join(tmpDir, "deploy", "kubernetes")
	err := os.MkdirAll(k8sDir, 0755)
	if err != nil {
		t.Fatalf("failed to create k8s dir: %v", err)
	}

	// Create test K8s manifests
	managedManifest := filepath.Join(k8sDir, "elastic-agent-managed-kubernetes.yaml")
	standaloneManifest := filepath.Join(k8sDir, "elastic-agent-standalone-kubernetes.yaml")

	manifestContent := `apiVersion: apps/v1
kind: DaemonSet
spec:
  template:
    spec:
      containers:
        - name: elastic-agent
          image: docker.elastic.co/elastic-agent/elastic-agent:9.4.0
`

	err = os.WriteFile(managedManifest, []byte(manifestContent), 0644)
	if err != nil {
		t.Fatalf("failed to write managed manifest: %v", err)
	}

	err = os.WriteFile(standaloneManifest, []byte(manifestContent), 0644)
	if err != nil {
		t.Fatalf("failed to write standalone manifest: %v", err)
	}

	// Change to temp directory
	originalWd, _ := os.Getwd()
	defer func() {
		if err := os.Chdir(originalWd); err != nil {
			t.Logf("failed to restore working directory: %v", err)
		}
	}()
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatalf("failed to change to temp directory: %v", err)
	}

	// Test UpdateDocs
	newVersion := "9.5.0"
	err = UpdateDocs(newVersion)
	if err != nil {
		t.Errorf("UpdateDocs() error = %v", err)
		return
	}

	// Verify both manifests were updated
	for _, manifest := range []string{managedManifest, standaloneManifest} {
		content, err := os.ReadFile(manifest)
		if err != nil {
			t.Fatalf("failed to read manifest: %v", err)
		}

		expectedImage := "docker.elastic.co/elastic-agent/elastic-agent:" + newVersion
		if !strings.Contains(string(content), expectedImage) {
			t.Errorf("UpdateDocs() manifest %s does not contain %s", manifest, expectedImage)
		}
	}
}

func TestUpdateVersionInFile(t *testing.T) {
	tmpDir := t.TempDir()

	tests := []struct {
		name        string
		content     string
		newVersion  string
		wantContent string
	}{
		{
			name: "update K8s manifest image tag",
			content: `apiVersion: apps/v1
kind: DaemonSet
spec:
  template:
    spec:
      containers:
        - name: elastic-agent
          image: docker.elastic.co/elastic-agent/elastic-agent:9.4.0
`,
			newVersion:  "9.5.0",
			wantContent: "docker.elastic.co/elastic-agent/elastic-agent:9.5.0",
		},
		{
			name:        "no change when pattern not found",
			content:     "some other content",
			newVersion:  "9.5.0",
			wantContent: "some other content",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testFile := filepath.Join(tmpDir, "test.yaml")
			err := os.WriteFile(testFile, []byte(tt.content), 0644)
			if err != nil {
				t.Fatalf("failed to write test file: %v", err)
			}

			err = updateVersionInFile(testFile, tt.newVersion)
			if err != nil {
				t.Errorf("updateVersionInFile() error = %v", err)
				return
			}

			content, err := os.ReadFile(testFile)
			if err != nil {
				t.Fatalf("failed to read test file: %v", err)
			}

			if !strings.Contains(string(content), tt.wantContent) {
				t.Errorf("updateVersionInFile() content = %v, want to contain %v", string(content), tt.wantContent)
			}
		})
	}
}

func TestUpdateMergify(t *testing.T) {
	tmpDir := t.TempDir()

	// Change to temp directory
	originalWd, _ := os.Getwd()
	defer func() {
		if err := os.Chdir(originalWd); err != nil {
			t.Logf("failed to restore working directory: %v", err)
		}
	}()
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatalf("failed to change to temp directory: %v", err)
	}

	// Create a basic .mergify.yml file
	mergifyContent := `pull_request_rules:
  - name: backport patches to 9.3 branch
    conditions:
      - merged
      - label=backport-9.3
    actions:
      backport:
        branches:
          - "9.3"
`
	err := os.WriteFile(".mergify.yml", []byte(mergifyContent), 0644)
	if err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	tests := []struct {
		name       string
		version    string
		wantBranch string
		wantLabel  string
	}{
		{
			name:       "add backport rule for 9.4",
			version:    "9.4.0",
			wantBranch: "9.4",
			wantLabel:  "backport-9.4",
		},
		{
			name:       "add backport rule for 9.5",
			version:    "9.5.0",
			wantBranch: "9.5",
			wantLabel:  "backport-9.5",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := UpdateMergify(tt.version)
			if err != nil {
				t.Errorf("UpdateMergify() error = %v", err)
				return
			}

			// Read and parse the updated file
			content, err := os.ReadFile(".mergify.yml")
			if err != nil {
				t.Fatalf("failed to read .mergify.yml: %v", err)
			}

			var config map[string]interface{}
			err = yaml.Unmarshal(content, &config)
			if err != nil {
				t.Fatalf("failed to parse .mergify.yml: %v", err)
			}

			rules, ok := config["pull_request_rules"].([]interface{})
			if !ok {
				t.Fatal("pull_request_rules not found")
			}

			// Check if the new rule was added
			found := false
			for _, rule := range rules {
				ruleMap, ok := rule.(map[string]interface{})
				if !ok {
					continue
				}

				conditions, ok := ruleMap["conditions"].([]interface{})
				if !ok {
					continue
				}

				for _, cond := range conditions {
					if condStr, ok := cond.(string); ok && condStr == "label="+tt.wantLabel {
						found = true
						break
					}
				}
			}

			if !found {
				t.Errorf("UpdateMergify() did not add label %s", tt.wantLabel)
			}
		})
	}
}

func TestUpdateMergifyIdempotent(t *testing.T) {
	tmpDir := t.TempDir()

	// Change to temp directory
	originalWd, _ := os.Getwd()
	defer func() {
		if err := os.Chdir(originalWd); err != nil {
			t.Logf("failed to restore working directory: %v", err)
		}
	}()
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatalf("failed to change to temp directory: %v", err)
	}

	// Create a basic .mergify.yml file
	mergifyContent := `pull_request_rules:
  - name: backport patches to 9.4 branch
    conditions:
      - merged
      - label=backport-9.4
    actions:
      backport:
        branches:
          - "9.4"
`
	err := os.WriteFile(".mergify.yml", []byte(mergifyContent), 0644)
	if err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	// First update
	err = UpdateMergify("9.4.0")
	if err != nil {
		t.Errorf("UpdateMergify() first call error = %v", err)
	}

	// Read the file after first update
	content1, err := os.ReadFile(".mergify.yml")
	if err != nil {
		t.Fatalf("failed to read .mergify.yml: %v", err)
	}

	// Second update with same version
	err = UpdateMergify("9.4.0")
	if err != nil {
		t.Errorf("UpdateMergify() second call error = %v", err)
	}

	// Read the file after second update
	content2, err := os.ReadFile(".mergify.yml")
	if err != nil {
		t.Fatalf("failed to read .mergify.yml: %v", err)
	}

	// The content should be the same (idempotent)
	if string(content1) != string(content2) {
		t.Error("UpdateMergify() is not idempotent - file changed on second call")
	}
}

func TestLoadReleaseConfigFromEnv(t *testing.T) {
	// Save original env vars
	originalVars := map[string]string{
		"CURRENT_RELEASE": os.Getenv("CURRENT_RELEASE"),
		"BASE_BRANCH":     os.Getenv("BASE_BRANCH"),
		"PROJECT_OWNER":   os.Getenv("PROJECT_OWNER"),
		"PROJECT_REPO":    os.Getenv("PROJECT_REPO"),
	}
	defer func() {
		for key, val := range originalVars {
			if val == "" {
				os.Unsetenv(key)
			} else {
				os.Setenv(key, val)
			}
		}
	}()

	tests := []struct {
		name      string
		envVars   map[string]string
		wantError bool
		validate  func(t *testing.T, cfg *ReleaseConfig)
	}{
		{
			name: "valid config with all env vars",
			envVars: map[string]string{
				"CURRENT_RELEASE": "9.5.0",
				"BASE_BRANCH":     "main",
				"PROJECT_OWNER":   "elastic",
				"PROJECT_REPO":    "elastic-agent",
			},
			wantError: false,
			validate: func(t *testing.T, cfg *ReleaseConfig) {
				if cfg.Version != "9.5.0" {
					t.Errorf("Version = %s, want 9.5.0", cfg.Version)
				}
				if cfg.ReleaseBranch != "9.5" {
					t.Errorf("ReleaseBranch = %s, want 9.5", cfg.ReleaseBranch)
				}
				if cfg.BaseBranch != "main" {
					t.Errorf("BaseBranch = %s, want main", cfg.BaseBranch)
				}
			},
		},
		{
			name: "missing version",
			envVars: map[string]string{
				"BASE_BRANCH": "main",
			},
			wantError: true,
		},
		{
			name: "invalid version format",
			envVars: map[string]string{
				"CURRENT_RELEASE": "invalid",
			},
			wantError: true,
		},
		{
			name: "defaults applied",
			envVars: map[string]string{
				"CURRENT_RELEASE": "9.5.0",
			},
			wantError: false,
			validate: func(t *testing.T, cfg *ReleaseConfig) {
				if cfg.BaseBranch != "main" {
					t.Errorf("BaseBranch = %s, want default 'main'", cfg.BaseBranch)
				}
				if cfg.Owner != "elastic" {
					t.Errorf("Owner = %s, want default 'elastic'", cfg.Owner)
				}
				if cfg.Repo != "elastic-agent" {
					t.Errorf("Repo = %s, want default 'elastic-agent'", cfg.Repo)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear env vars
			os.Unsetenv("CURRENT_RELEASE")
			os.Unsetenv("BASE_BRANCH")
			os.Unsetenv("PROJECT_OWNER")
			os.Unsetenv("PROJECT_REPO")

			// Set test env vars
			for key, val := range tt.envVars {
				os.Setenv(key, val)
			}

			cfg, err := LoadReleaseConfigFromEnv()
			if (err != nil) != tt.wantError {
				t.Errorf("LoadReleaseConfigFromEnv() error = %v, wantError %v", err, tt.wantError)
				return
			}

			if !tt.wantError && tt.validate != nil {
				tt.validate(t, cfg)
			}
		})
	}
}

func TestPrepareMajorMinorRelease(t *testing.T) {
	tmpDir := t.TempDir()

	// Change to temp directory
	originalWd, _ := os.Getwd()
	defer func() {
		if err := os.Chdir(originalWd); err != nil {
			t.Logf("failed to restore working directory: %v", err)
		}
	}()
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatalf("failed to change to temp directory: %v", err)
	}

	// Create required directory structure
	versionDir := filepath.Join(tmpDir, "version")
	k8sDir := filepath.Join(tmpDir, "deploy", "kubernetes")
	err := os.MkdirAll(versionDir, 0755)
	if err != nil {
		t.Fatalf("failed to create version dir: %v", err)
	}
	err = os.MkdirAll(k8sDir, 0755)
	if err != nil {
		t.Fatalf("failed to create k8s dir: %v", err)
	}

	// Create test files
	versionFile := filepath.Join(versionDir, "version.go")
	err = os.WriteFile(versionFile, []byte(`package version

const defaultBeatVersion = "9.4.0"
const Agent = defaultBeatVersion
`), 0644)
	if err != nil {
		t.Fatalf("failed to write version file: %v", err)
	}

	managedManifest := filepath.Join(k8sDir, "elastic-agent-managed-kubernetes.yaml")
	standaloneManifest := filepath.Join(k8sDir, "elastic-agent-standalone-kubernetes.yaml")
	manifestContent := `image: docker.elastic.co/elastic-agent/elastic-agent:9.4.0`

	err = os.WriteFile(managedManifest, []byte(manifestContent), 0644)
	if err != nil {
		t.Fatalf("failed to write managed manifest: %v", err)
	}
	err = os.WriteFile(standaloneManifest, []byte(manifestContent), 0644)
	if err != nil {
		t.Fatalf("failed to write standalone manifest: %v", err)
	}

	// Create .mergify.yml
	mergifyContent := `pull_request_rules: []`
	err = os.WriteFile(".mergify.yml", []byte(mergifyContent), 0644)
	if err != nil {
		t.Fatalf("failed to write mergify file: %v", err)
	}

	// Test PrepareMajorMinorRelease
	cfg := &ReleaseConfig{
		Version:       "9.5.0",
		BaseBranch:    "main",
		ReleaseBranch: "9.5",
		Owner:         "elastic",
		Repo:          "elastic-agent",
		AuthorName:    "Test User",
		AuthorEmail:   "test@example.com",
	}

	err = PrepareMajorMinorRelease(cfg)
	if err != nil {
		t.Errorf("PrepareMajorMinorRelease() error = %v", err)
		return
	}

	// Verify version was updated
	versionContent, err := os.ReadFile(versionFile)
	if err != nil {
		t.Fatalf("failed to read version file: %v", err)
	}
	if !strings.Contains(string(versionContent), "9.5.0") {
		t.Error("Version file was not updated")
	}

	// Verify manifests were updated
	managedContent, err := os.ReadFile(managedManifest)
	if err != nil {
		t.Fatalf("failed to read managed manifest: %v", err)
	}
	if !strings.Contains(string(managedContent), "9.5.0") {
		t.Error("Managed manifest was not updated")
	}
}

func TestCreateReleaseBranch(t *testing.T) {
	tmpDir := t.TempDir()

	// Initialize a git repository
	gitRepo, err := git.PlainInit(tmpDir, false)
	if err != nil {
		t.Fatalf("failed to init repo: %v", err)
	}

	// Create an initial commit
	w, err := gitRepo.Worktree()
	if err != nil {
		t.Fatalf("failed to get worktree: %v", err)
	}

	testFile := filepath.Join(tmpDir, "README.md")
	err = os.WriteFile(testFile, []byte("# Test"), 0644)
	if err != nil {
		t.Fatalf("failed to write file: %v", err)
	}

	_, err = w.Add("README.md")
	if err != nil {
		t.Fatalf("failed to add file: %v", err)
	}

	_, err = w.Commit("Initial commit", &git.CommitOptions{
		Author: &object.Signature{
			Name:  "Test",
			Email: "test@example.com",
		},
	})
	if err != nil {
		t.Fatalf("failed to commit: %v", err)
	}

	// Test CreateReleaseBranch
	cfg := &ReleaseConfig{
		Version:       "9.5.0",
		BaseBranch:    "main",
		ReleaseBranch: "9.5",
		Owner:         "elastic",
		Repo:          "elastic-agent",
		AuthorName:    "Test User",
		AuthorEmail:   "test@example.com",
	}

	// Create another file to commit
	changeFile := filepath.Join(tmpDir, "change.txt")
	err = os.WriteFile(changeFile, []byte("changes"), 0644)
	if err != nil {
		t.Fatalf("failed to write change file: %v", err)
	}

	err = CreateReleaseBranch(cfg, tmpDir)
	if err != nil {
		t.Errorf("CreateReleaseBranch() error = %v", err)
		return
	}

	// Verify the branch was created
	repo, err := OpenRepo(tmpDir)
	if err != nil {
		t.Fatalf("failed to open repo: %v", err)
	}

	currentBranch, err := repo.GetCurrentBranch()
	if err != nil {
		t.Errorf("GetCurrentBranch() error = %v", err)
		return
	}

	if currentBranch != cfg.ReleaseBranch {
		t.Errorf("CreateReleaseBranch() branch = %s, want %s", currentBranch, cfg.ReleaseBranch)
	}
}
