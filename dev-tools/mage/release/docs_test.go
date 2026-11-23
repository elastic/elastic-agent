// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package release

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestApplyVersionReplacements(t *testing.T) {
	tests := []struct {
		name       string
		path       string
		content    string
		newVersion string
		want       []string
	}{
		{
			name:       "plain k8s manifest",
			path:       "deploy/kubernetes/elastic-agent-managed-kubernetes.yaml",
			content:    "image: docker.elastic.co/elastic-agent/elastic-agent:9.5.0\n",
			newVersion: "9.6.0",
			want:       []string{"docker.elastic.co/elastic-agent/elastic-agent:9.6.0"},
		},
		{
			name: "helm rendered manifest",
			path: "deploy/helm/elastic-agent/examples/fleet-managed/rendered/manifest.yaml",
			content: `helm.sh/chart: elastic-agent-9.5.0-SNAPSHOT
app.kubernetes.io/version: 9.5.0
image: docker.elastic.co/elastic-agent/elastic-agent:9.5.0-SNAPSHOT
`,
			newVersion: "9.6.0",
			want: []string{
				"helm.sh/chart: elastic-agent-9.6.0-SNAPSHOT",
				"app.kubernetes.io/version: 9.6.0",
				"docker.elastic.co/elastic-agent/elastic-agent:9.6.0-SNAPSHOT",
			},
		},
		{
			name: "chart yaml",
			path: "deploy/helm/elastic-agent/Chart.yaml",
			content: `appVersion: 9.5.0
version: 9.5.0-SNAPSHOT
`,
			newVersion: "9.6.0",
			want: []string{
				"appVersion: 9.6.0",
				"version: 9.6.0-SNAPSHOT",
			},
		},
		{
			name: "helm values",
			path: "deploy/helm/elastic-agent/values.yaml",
			content: `agent:
  version: 9.5.0
  image:
    tag: "9.5.0-SNAPSHOT"
`,
			newVersion: "9.6.0",
			want: []string{
				"version: 9.6.0",
				`tag: "9.6.0-SNAPSHOT"`,
			},
		},
		{
			name: "edot collector values",
			path: "deploy/helm/edot-collector/kube-stack/values.yaml",
			content: `defaultCRConfig:
  image:
    tag: "9.5.0"
`,
			newVersion: "9.6.0",
			want:       []string{`tag: "9.6.0"`},
		},
		{
			name: "kustomize manifest",
			path: "deploy/kubernetes/elastic-agent-kustomize/default/elastic-agent-managed/base/elastic-agent-managed-daemonset.yaml",
			content: `image: docker.elastic.co/elastic-agent/elastic-agent:9.5.0
curl -sL https://github.com/elastic/elastic-agent/archive/refs/tags/v9.5.0.tar.gz | tar xz -C /etc/elastic-agent/inputs.d --strip=5 "elastic-agent-9.5.0/deploy/kubernetes/elastic-agent-standalone/templates.d"
`,
			newVersion: "9.6.0",
			want: []string{
				"docker.elastic.co/elastic-agent/elastic-agent:9.6.0",
				"refs/tags/v9.6.0.tar.gz",
				"elastic-agent-9.6.0/deploy/kubernetes",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := applyVersionReplacements(tt.path, tt.content, tt.newVersion)
			for _, want := range tt.want {
				require.Contains(t, got, want, "applyVersionReplacements() missing %q", want)
			}
		})
	}
}

func TestUpdateDocsCoversReleaseFiles(t *testing.T) {
	tmpDir := t.TempDir()

	files := map[string]string{
		"deploy/kubernetes/elastic-agent-managed-kubernetes.yaml":    "image: docker.elastic.co/elastic-agent/elastic-agent:9.5.0",
		"deploy/kubernetes/elastic-agent-standalone-kubernetes.yaml": "image: docker.elastic.co/elastic-agent/elastic-agent:9.5.0",
		"deploy/helm/elastic-agent/Chart.yaml": `appVersion: 9.5.0
version: 9.5.0-SNAPSHOT
`,
		"deploy/helm/elastic-agent/values.yaml": `agent:
  version: 9.5.0
  image:
    tag: "9.5.0-SNAPSHOT"
`,
		"deploy/helm/edot-collector/kube-stack/values.yaml": `defaultCRConfig:
  image:
    tag: "9.5.0"
`,
		"deploy/helm/elastic-agent/examples/fleet-managed/rendered/manifest.yaml": `image: docker.elastic.co/elastic-agent/elastic-agent:9.5.0-SNAPSHOT
helm.sh/chart: elastic-agent-9.5.0-SNAPSHOT
`,
		"deploy/kubernetes/elastic-agent-kustomize/default/elastic-agent-managed/base/elastic-agent-managed-daemonset.yaml": "image: docker.elastic.co/elastic-agent/elastic-agent:9.5.0",
		"testing/integration/k8s/testdata/elastic-agent-kustomize.yaml":                                                     "image: docker.elastic.co/elastic-agent/elastic-agent:9.5.0",
	}

	for relPath, content := range files {
		fullPath := filepath.Join(tmpDir, relPath)
		require.NoError(t, os.MkdirAll(filepath.Dir(fullPath), 0755), "failed to create dir for %s", relPath)
		require.NoError(t, os.WriteFile(fullPath, []byte(content), 0644), "failed to write %s", relPath)
	}

	originalWd, _ := os.Getwd()
	defer func() {
		_ = os.Chdir(originalWd)
	}()
	require.NoError(t, os.Chdir(tmpDir), "failed to change to temp directory")

	require.NoError(t, UpdateDocs("9.6.0"), "UpdateDocs() error")

	for relPath := range files {
		content, err := os.ReadFile(filepath.Join(tmpDir, relPath))
		require.NoError(t, err, "failed to read %s", relPath)
		require.NotContains(t, string(content), "9.5.0", "file %s still contains old version 9.5.0:\n%s", relPath, string(content))
	}
}

func TestIsReleaseWritablePath(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{path: "version/version.go", want: true},
		{path: filepath.FromSlash("version/version.go"), want: true},
		{path: `version\version.go`, want: true},
		{path: "deploy/helm/elastic-agent/Chart.yaml", want: true},
		{path: filepath.FromSlash("deploy/kubernetes/elastic-agent-managed-kubernetes.yaml"), want: true},
		{path: `deploy\kubernetes\elastic-agent-managed-kubernetes.yaml`, want: true},
		{path: "testing/integration/k8s/testdata/elastic-agent-kustomize.yaml", want: true},
		{path: filepath.FromSlash("testing/integration/k8s/testdata/elastic-agent-kustomize.yaml"), want: true},
		{path: ".mergify.yml", want: true},
		{path: "README.md", want: true},
		{path: "../outside", want: false},
		{path: filepath.FromSlash("../outside"), want: false},
		{path: `..\outside`, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := isReleaseWritablePath(tt.path)
			require.Equal(t, tt.want, got, "isReleaseWritablePath(%q)", tt.path)
		})
	}
}
