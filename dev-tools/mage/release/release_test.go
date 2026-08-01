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
	"github.com/go-git/go-git/v5/plumbing"
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

func TestUpdateDeploymentManifests(t *testing.T) {
	tmpDir := t.TempDir()
	origDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Chdir(origDir)
	})
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatalf("chdir: %v", err)
	}

	manifest := "deploy/kubernetes/elastic-agent-managed-kubernetes.yaml"
	if err := os.MkdirAll(filepath.Dir(manifest), 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(manifest, []byte("image: docker.elastic.co/elastic-agent/elastic-agent:9.6.0\n"), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
	asciidoc := "version/docs/version.asciidoc"
	if err := os.MkdirAll(filepath.Dir(asciidoc), 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(asciidoc, []byte(":stack-version: 9.6.0\n:doc-branch: main\n"), 0644); err != nil {
		t.Fatalf("write asciidoc: %v", err)
	}

	if err := UpdateDeploymentManifests("9.6.1"); err != nil {
		t.Fatalf("UpdateDeploymentManifests: %v", err)
	}

	got, err := os.ReadFile(manifest)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !strings.Contains(string(got), "elastic-agent:9.6.1") {
		t.Fatalf("manifest = %q, want 9.6.1 image", got)
	}
	adoc, err := os.ReadFile(asciidoc)
	if err != nil {
		t.Fatalf("read asciidoc: %v", err)
	}
	if !strings.Contains(string(adoc), ":stack-version: 9.6.0") {
		t.Fatalf("asciidoc should be unchanged, got %q", adoc)
	}
}

func TestUpdateVersionInFile(t *testing.T) {
	tmpDir := t.TempDir()
	manifestPath := filepath.Join("deploy", "kubernetes", "elastic-agent-managed-kubernetes.yaml")

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
			err := os.MkdirAll(filepath.Dir(manifestPath), 0755)
			if err != nil {
				t.Fatalf("failed to create manifest dir: %v", err)
			}

			err = os.WriteFile(manifestPath, []byte(tt.content), 0644)
			if err != nil {
				t.Fatalf("failed to write test file: %v", err)
			}

			err = updateVersionInFile(manifestPath, tt.newVersion)
			if err != nil {
				t.Errorf("updateVersionInFile() error = %v", err)
				return
			}

			content, err := os.ReadFile(manifestPath)
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

func TestUpdateVersionIdempotent(t *testing.T) {
	tmpDir := t.TempDir()
	versionDir := filepath.Join(tmpDir, "version")
	err := os.Mkdir(versionDir, 0755)
	if err != nil {
		t.Fatalf("failed to create version dir: %v", err)
	}

	versionFile := filepath.Join(versionDir, "version.go")
	initialContent := `package version

const defaultBeatVersion = "9.5.0"
const Agent = defaultBeatVersion
`
	err = os.WriteFile(versionFile, []byte(initialContent), 0644)
	if err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	originalWd, _ := os.Getwd()
	defer func() {
		if err := os.Chdir(originalWd); err != nil {
			t.Logf("failed to restore working directory: %v", err)
		}
	}()
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatalf("failed to change to temp directory: %v", err)
	}

	err = UpdateVersion("9.5.0")
	if err != nil {
		t.Errorf("UpdateVersion() first call error = %v", err)
	}

	content1, err := os.ReadFile(versionFile)
	if err != nil {
		t.Fatalf("failed to read version file: %v", err)
	}

	err = UpdateVersion("9.5.0")
	if err != nil {
		t.Errorf("UpdateVersion() second call error = %v", err)
	}

	content2, err := os.ReadFile(versionFile)
	if err != nil {
		t.Fatalf("failed to read version file: %v", err)
	}

	if string(content1) != string(content2) {
		t.Error("UpdateVersion() is not idempotent - file changed on second call")
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

func TestUpdatePatchDocs(t *testing.T) {
	tmpDir := t.TempDir()
	docsDir := filepath.Join(tmpDir, "version", "docs")
	if err := os.MkdirAll(docsDir, 0755); err != nil {
		t.Fatalf("failed to create docs dir: %v", err)
	}

	asciidocPath := filepath.Join(docsDir, "version.asciidoc")
	if err := os.WriteFile(asciidocPath, []byte(`:stack-version: 9.4.2
:doc-branch: 9.4
`), 0644); err != nil {
		t.Fatalf("failed to write asciidoc: %v", err)
	}

	originalWd, _ := os.Getwd()
	defer func() {
		_ = os.Chdir(originalWd)
	}()
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatalf("failed to change to temp directory: %v", err)
	}

	if err := UpdatePatchDocs("9.4.3"); err != nil {
		t.Fatalf("UpdatePatchDocs() error = %v", err)
	}

	content, err := os.ReadFile(asciidocPath)
	if err != nil {
		t.Fatalf("failed to read asciidoc: %v", err)
	}
	if !strings.Contains(string(content), ":stack-version: 9.4.3") {
		t.Errorf("UpdatePatchDocs() content = %q, want stack-version 9.4.3", string(content))
	}
	if strings.Contains(string(content), ":stack-version: 9.4.2") {
		t.Errorf("UpdatePatchDocs() still contains old stack version")
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
		CurrentRelease: "9.5.0",
		BaseBranch:     "main",
		ReleaseBranch:  "9.5",
		ProjectOwner:   "elastic",
		ProjectRepo:    "elastic-agent",
		GitAuthorName:  "Test User",
		GitAuthorEmail: "test@example.com",
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

func TestPatchPRBodies(t *testing.T) {
	body := patchBeforeBuildPRBody("9.7.1")
	if !strings.Contains(body, "9.7.1") {
		t.Errorf("patchBeforeBuildPRBody() = %q, want version", body)
	}
	if !strings.Contains(body, "before the final Release build") {
		t.Errorf("patchBeforeBuildPRBody() = %q, want merge guidance", body)
	}
	if !strings.Contains(body, "Does **not** bump version/version.go") {
		t.Errorf("patchBeforeBuildPRBody() = %q, want version.go not bumped note", body)
	}
}

func TestCreateReleaseBranch(t *testing.T) {
	tmpDir := t.TempDir()

	gitRepo, err := git.PlainInit(tmpDir, false)
	if err != nil {
		t.Fatalf("failed to init repo: %v", err)
	}

	w, err := gitRepo.Worktree()
	if err != nil {
		t.Fatalf("failed to get worktree: %v", err)
	}

	versionDir := filepath.Join(tmpDir, "version")
	k8sDir := filepath.Join(tmpDir, "deploy", "kubernetes")
	if err := os.MkdirAll(versionDir, 0755); err != nil {
		t.Fatalf("failed to create version dir: %v", err)
	}
	if err := os.MkdirAll(k8sDir, 0755); err != nil {
		t.Fatalf("failed to create k8s dir: %v", err)
	}

	files := map[string]string{
		"README.md": "# Test",
		filepath.Join("version", "version.go"): `package version

const defaultBeatVersion = "9.4.0"
`,
		filepath.Join("deploy", "kubernetes", "elastic-agent-managed-kubernetes.yaml"):    "image: docker.elastic.co/elastic-agent/elastic-agent:9.4.0",
		filepath.Join("deploy", "kubernetes", "elastic-agent-standalone-kubernetes.yaml"): "image: docker.elastic.co/elastic-agent/elastic-agent:9.4.0",
		".mergify.yml": "pull_request_rules: []",
	}
	for relPath, content := range files {
		fullPath := filepath.Join(tmpDir, relPath)
		if err := os.MkdirAll(filepath.Dir(fullPath), 0755); err != nil {
			t.Fatalf("failed to create dir for %s: %v", relPath, err)
		}
		if err := os.WriteFile(fullPath, []byte(content), 0644); err != nil {
			t.Fatalf("failed to write %s: %v", relPath, err)
		}
		if _, err := w.Add(relPath); err != nil {
			t.Fatalf("failed to add %s: %v", relPath, err)
		}
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

	headRef, err := gitRepo.Head()
	if err != nil {
		t.Fatalf("failed to get HEAD: %v", err)
	}
	mainRef := plumbing.NewHashReference(plumbing.NewBranchReferenceName("main"), headRef.Hash())
	if err := gitRepo.Storer.SetReference(mainRef); err != nil {
		t.Fatalf("failed to create main branch: %v", err)
	}
	if err := w.Checkout(&git.CheckoutOptions{Branch: plumbing.NewBranchReferenceName("main")}); err != nil {
		t.Fatalf("failed to checkout main: %v", err)
	}
	_ = gitRepo.Storer.RemoveReference(plumbing.NewBranchReferenceName("master"))

	cfg := &ReleaseConfig{
		CurrentRelease: "9.5.0",
		BaseBranch:     "main",
		ReleaseBranch:  "9.5",
		ProjectOwner:   "elastic",
		ProjectRepo:    "elastic-agent",
		GitAuthorName:  "Test User",
		GitAuthorEmail: "test@example.com",
	}

	err = CreateReleaseBranch(cfg, tmpDir)
	if err != nil {
		t.Errorf("CreateReleaseBranch() error = %v", err)
		return
	}

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
