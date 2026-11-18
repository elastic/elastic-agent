// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package release

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestUpdateVersion(t *testing.T) {
	// Create a temporary directory for test files
	tmpDir := t.TempDir()
	versionDir := filepath.Join(tmpDir, "version")
	require.NoError(t, os.Mkdir(versionDir, 0755), "failed to create version dir")

	versionFile := filepath.Join(versionDir, "version.go")
	initialContent := `// Copyright notice

package version

const defaultBeatVersion = "9.4.0"
const Agent = defaultBeatVersion
`
	require.NoError(t, os.WriteFile(versionFile, []byte(initialContent), 0644), "failed to write test file")

	// Change to temp directory
	originalWd, _ := os.Getwd()
	defer func() {
		if err := os.Chdir(originalWd); err != nil {
			t.Logf("failed to restore working directory: %v", err)
		}
	}()
	require.NoError(t, os.Chdir(tmpDir), "failed to change to temp directory")

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
			if tt.wantError {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)

			content, err := os.ReadFile(versionFile)
			require.NoError(t, err, "failed to read version file")
			require.Contains(t, string(content), tt.wantVersion)
		})
	}
}

func TestUpdateDocs(t *testing.T) {
	// Create a temporary directory for test files
	tmpDir := t.TempDir()

	// Create deploy/kubernetes directory
	k8sDir := filepath.Join(tmpDir, "deploy", "kubernetes")
	require.NoError(t, os.MkdirAll(k8sDir, 0755), "failed to create k8s dir")

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

	require.NoError(t, os.WriteFile(managedManifest, []byte(manifestContent), 0644), "failed to write managed manifest")
	require.NoError(t, os.WriteFile(standaloneManifest, []byte(manifestContent), 0644), "failed to write standalone manifest")

	// Change to temp directory
	originalWd, _ := os.Getwd()
	defer func() {
		if err := os.Chdir(originalWd); err != nil {
			t.Logf("failed to restore working directory: %v", err)
		}
	}()
	require.NoError(t, os.Chdir(tmpDir), "failed to change to temp directory")

	// Test UpdateDocs
	newVersion := "9.5.0"
	require.NoError(t, UpdateDocs(newVersion))

	// Verify both manifests were updated
	for _, manifest := range []string{managedManifest, standaloneManifest} {
		content, err := os.ReadFile(manifest)
		require.NoError(t, err, "failed to read manifest")

		expectedImage := "docker.elastic.co/elastic-agent/elastic-agent:" + newVersion
		require.Contains(t, string(content), expectedImage, "UpdateDocs() manifest %s", manifest)
	}
}

func TestUpdateDeploymentManifests(t *testing.T) {
	tmpDir := t.TempDir()
	origDir, err := os.Getwd()
	require.NoError(t, err, "getwd")
	t.Cleanup(func() {
		_ = os.Chdir(origDir)
	})
	require.NoError(t, os.Chdir(tmpDir), "chdir")

	manifest := "deploy/kubernetes/elastic-agent-managed-kubernetes.yaml"
	require.NoError(t, os.MkdirAll(filepath.Dir(manifest), 0755), "mkdir")
	require.NoError(t, os.WriteFile(manifest, []byte("image: docker.elastic.co/elastic-agent/elastic-agent:9.6.0\n"), 0644), "write")
	asciidoc := "version/docs/version.asciidoc"
	require.NoError(t, os.MkdirAll(filepath.Dir(asciidoc), 0755), "mkdir")
	require.NoError(t, os.WriteFile(asciidoc, []byte(":stack-version: 9.6.0\n:doc-branch: main\n"), 0644), "write asciidoc")

	require.NoError(t, UpdateDeploymentManifests("9.6.1"), "UpdateDeploymentManifests")

	got, err := os.ReadFile(manifest)
	require.NoError(t, err, "read")
	require.Contains(t, string(got), "elastic-agent:9.6.1", "manifest = %q, want 9.6.1 image", got)

	adoc, err := os.ReadFile(asciidoc)
	require.NoError(t, err, "read asciidoc")
	require.Contains(t, string(adoc), ":stack-version: 9.6.0", "asciidoc should be unchanged, got %q", adoc)
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
	require.NoError(t, os.Chdir(tmpDir), "failed to change to temp directory")

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
			require.NoError(t, os.MkdirAll(filepath.Dir(manifestPath), 0755), "failed to create manifest dir")
			require.NoError(t, os.WriteFile(manifestPath, []byte(tt.content), 0644), "failed to write test file")
			require.NoError(t, updateVersionInFile(manifestPath, tt.newVersion))

			content, err := os.ReadFile(manifestPath)
			require.NoError(t, err, "failed to read test file")
			require.Contains(t, string(content), tt.wantContent)
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
	require.NoError(t, os.Chdir(tmpDir), "failed to change to temp directory")

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
	require.NoError(t, os.WriteFile(".mergify.yml", []byte(mergifyContent), 0644), "failed to write test file")

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
			require.NoError(t, UpdateMergify(tt.version))

			// Read and parse the updated file
			content, err := os.ReadFile(".mergify.yml")
			require.NoError(t, err, "failed to read .mergify.yml")

			var config map[string]interface{}
			require.NoError(t, yaml.Unmarshal(content, &config), "failed to parse .mergify.yml")

			rules, ok := config["pull_request_rules"].([]interface{})
			require.True(t, ok, "pull_request_rules not found")

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

			require.True(t, found, "UpdateMergify() did not add label %s", tt.wantLabel)
		})
	}
}

func TestUpdateVersionIdempotent(t *testing.T) {
	tmpDir := t.TempDir()
	versionDir := filepath.Join(tmpDir, "version")
	require.NoError(t, os.Mkdir(versionDir, 0755), "failed to create version dir")

	versionFile := filepath.Join(versionDir, "version.go")
	initialContent := `package version

const defaultBeatVersion = "9.5.0"
const Agent = defaultBeatVersion
`
	require.NoError(t, os.WriteFile(versionFile, []byte(initialContent), 0644), "failed to write test file")

	originalWd, _ := os.Getwd()
	defer func() {
		if err := os.Chdir(originalWd); err != nil {
			t.Logf("failed to restore working directory: %v", err)
		}
	}()
	require.NoError(t, os.Chdir(tmpDir), "failed to change to temp directory")

	require.NoError(t, UpdateVersion("9.5.0"), "UpdateVersion() first call")

	content1, err := os.ReadFile(versionFile)
	require.NoError(t, err, "failed to read version file")

	require.NoError(t, UpdateVersion("9.5.0"), "UpdateVersion() second call")

	content2, err := os.ReadFile(versionFile)
	require.NoError(t, err, "failed to read version file")
	require.Equal(t, string(content1), string(content2), "UpdateVersion() is not idempotent - file changed on second call")
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
	require.NoError(t, os.Chdir(tmpDir), "failed to change to temp directory")

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
	require.NoError(t, os.WriteFile(".mergify.yml", []byte(mergifyContent), 0644), "failed to write test file")

	// First update
	require.NoError(t, UpdateMergify("9.4.0"), "UpdateMergify() first call")

	// Read the file after first update
	content1, err := os.ReadFile(".mergify.yml")
	require.NoError(t, err, "failed to read .mergify.yml")

	// Second update with same version
	require.NoError(t, UpdateMergify("9.4.0"), "UpdateMergify() second call")

	// Read the file after second update
	content2, err := os.ReadFile(".mergify.yml")
	require.NoError(t, err, "failed to read .mergify.yml")

	// The content should be the same (idempotent)
	require.Equal(t, string(content1), string(content2), "UpdateMergify() is not idempotent - file changed on second call")
}

func TestUpdatePatchDocs(t *testing.T) {
	tmpDir := t.TempDir()
	docsDir := filepath.Join(tmpDir, "version", "docs")
	require.NoError(t, os.MkdirAll(docsDir, 0755), "failed to create docs dir")

	asciidocPath := filepath.Join(docsDir, "version.asciidoc")
	require.NoError(t, os.WriteFile(asciidocPath, []byte(`:stack-version: 9.4.2
:doc-branch: 9.4
`), 0644), "failed to write asciidoc")

	originalWd, _ := os.Getwd()
	defer func() {
		_ = os.Chdir(originalWd)
	}()
	require.NoError(t, os.Chdir(tmpDir), "failed to change to temp directory")

	require.NoError(t, UpdatePatchDocs("9.4.3"), "UpdatePatchDocs() error")

	content, err := os.ReadFile(asciidocPath)
	require.NoError(t, err, "failed to read asciidoc")
	require.Contains(t, string(content), ":stack-version: 9.4.3", "UpdatePatchDocs() content = %q, want stack-version 9.4.3", string(content))
	require.NotContains(t, string(content), ":stack-version: 9.4.2", "UpdatePatchDocs() still contains old stack version")
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
	require.NoError(t, os.Chdir(tmpDir), "failed to change to temp directory")

	// Create required directory structure
	versionDir := filepath.Join(tmpDir, "version")
	k8sDir := filepath.Join(tmpDir, "deploy", "kubernetes")
	require.NoError(t, os.MkdirAll(versionDir, 0755), "failed to create version dir")
	require.NoError(t, os.MkdirAll(k8sDir, 0755), "failed to create k8s dir")

	// Create test files
	versionFile := filepath.Join(versionDir, "version.go")
	require.NoError(t, os.WriteFile(versionFile, []byte(`package version

const defaultBeatVersion = "9.4.0"
const Agent = defaultBeatVersion
`), 0644), "failed to write version file")

	managedManifest := filepath.Join(k8sDir, "elastic-agent-managed-kubernetes.yaml")
	standaloneManifest := filepath.Join(k8sDir, "elastic-agent-standalone-kubernetes.yaml")
	manifestContent := `image: docker.elastic.co/elastic-agent/elastic-agent:9.4.0`

	require.NoError(t, os.WriteFile(managedManifest, []byte(manifestContent), 0644), "failed to write managed manifest")
	require.NoError(t, os.WriteFile(standaloneManifest, []byte(manifestContent), 0644), "failed to write standalone manifest")

	// Create .mergify.yml
	mergifyContent := `pull_request_rules: []`
	require.NoError(t, os.WriteFile(".mergify.yml", []byte(mergifyContent), 0644), "failed to write mergify file")

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

	require.NoError(t, PrepareMajorMinorRelease(cfg))

	// Verify version was updated
	versionContent, err := os.ReadFile(versionFile)
	require.NoError(t, err, "failed to read version file")
	require.Contains(t, string(versionContent), "9.5.0", "Version file was not updated")

	// Verify manifests were updated
	managedContent, err := os.ReadFile(managedManifest)
	require.NoError(t, err, "failed to read managed manifest")
	require.Contains(t, string(managedContent), "9.5.0", "Managed manifest was not updated")
}

func TestPatchPRBodies(t *testing.T) {
	body := patchBeforeBuildPRBody("9.7.1")
	require.Contains(t, body, "9.7.1", "patchBeforeBuildPRBody() = %q, want version", body)
	require.Contains(t, body, "before the final Release build", "patchBeforeBuildPRBody() = %q, want merge guidance", body)
	require.Contains(t, body, "Does **not** bump version/version.go", "patchBeforeBuildPRBody() = %q, want version.go not bumped note", body)
}
