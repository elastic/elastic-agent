// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package release

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

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
	defer os.Chdir(originalWd)
	os.Chdir(tmpDir)

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
	defer os.Chdir(originalWd)
	os.Chdir(tmpDir)

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
			newVersion: "9.5.0",
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
	defer os.Chdir(originalWd)
	os.Chdir(tmpDir)

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
	defer os.Chdir(originalWd)
	os.Chdir(tmpDir)

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
