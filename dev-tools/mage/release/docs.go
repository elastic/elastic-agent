// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package release

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

const semverCore = `\d+\.\d+\.\d+`

var releaseWritablePrefixes = []string{
	"version/",
	"deploy/",
	"testing/integration/k8s/testdata/",
}

func isReleaseWritablePath(path string) bool {
	if path == ".mergify.yml" {
		return true
	}
	for _, prefix := range releaseWritablePrefixes {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

func collectDocFiles() ([]string, error) {
	files := []string{
		"deploy/kubernetes/elastic-agent-managed-kubernetes.yaml",
		"deploy/kubernetes/elastic-agent-standalone-kubernetes.yaml",
		"deploy/helm/elastic-agent/Chart.yaml",
		"deploy/helm/elastic-agent/values.yaml",
		"deploy/helm/edot-collector/kube-stack/values.yaml",
		"deploy/helm/edot-collector/kube-stack/managed_otlp/values.yaml",
		"deploy/helm/edot-collector/kube-stack/managed_otlp/logs-values.yaml",
		"testing/integration/k8s/testdata/elastic-agent-kustomize.yaml",
	}

	walkYAML := func(root string) error {
		return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				return nil
			}
			if !strings.HasSuffix(path, ".yaml") && !strings.HasSuffix(path, ".yml") {
				return nil
			}
			files = append(files, path)
			return nil
		})
	}

	if err := filepath.WalkDir("deploy/helm/elastic-agent/examples", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if strings.HasSuffix(path, "rendered/manifest.yaml") {
			files = append(files, path)
		}
		return nil
	}); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("failed to walk helm examples: %w", err)
	}
	if err := walkYAML("deploy/kubernetes/elastic-agent-kustomize"); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("failed to walk kustomize manifests: %w", err)
	}

	return files, nil
}

func snapshotVersion(version string) string {
	return version + "-SNAPSHOT"
}

func applyVersionReplacements(path, content, newVersion string) string {
	snapshot := snapshotVersion(newVersion)

	switch {
	case strings.HasSuffix(path, "Chart.yaml"):
		return updateChartYAML(content, newVersion, snapshot)
	case strings.HasSuffix(path, "deploy/helm/elastic-agent/values.yaml"):
		return updateHelmAgentValues(content, newVersion, snapshot)
	case strings.Contains(path, "edot-collector") && strings.HasSuffix(path, ".yaml"):
		return updateEdotCollectorValues(content, newVersion)
	case strings.Contains(path, "rendered/manifest.yaml"):
		return updateHelmRenderedManifest(content, newVersion, snapshot)
	case strings.Contains(path, "elastic-agent-kustomize"):
		return updateKustomizeManifest(content, newVersion)
	default:
		return updatePlainK8sManifest(content, newVersion)
	}
}

func updatePlainK8sManifest(content, newVersion string) string {
	re := regexp.MustCompile(`(docker\.elastic\.co/elastic-agent/elastic-agent:)` + semverCore + `(?:-SNAPSHOT)?`)
	return re.ReplaceAllString(content, `${1}`+newVersion)
}

func updateHelmRenderedManifest(content, newVersion, snapshot string) string {
	replacements := []struct {
		pattern string
		replace string
	}{
		{`(docker\.elastic\.co/elastic-agent/elastic-agent:)` + semverCore + `(?:-SNAPSHOT)?`, `${1}` + snapshot},
		{`(helm\.sh/chart: elastic-agent-)` + semverCore + `(?:-SNAPSHOT)?`, `${1}` + snapshot},
		{`(app\.kubernetes\.io/version: )` + semverCore, `${1}` + newVersion},
	}

	for _, r := range replacements {
		content = regexp.MustCompile(r.pattern).ReplaceAllString(content, r.replace)
	}
	return content
}

func updateKustomizeManifest(content, newVersion string) string {
	replacements := []struct {
		pattern string
		replace string
	}{
		{`(docker\.elastic\.co/elastic-agent/elastic-agent:)` + semverCore + `(?:-SNAPSHOT)?`, `${1}` + newVersion},
		{`(refs/tags/v)` + semverCore + `(\.tar\.gz)`, `${1}` + newVersion + `${2}`},
		{`("elastic-agent-)` + semverCore + `(/deploy/kubernetes)`, `${1}` + newVersion + `${2}`},
	}

	for _, r := range replacements {
		content = regexp.MustCompile(r.pattern).ReplaceAllString(content, r.replace)
	}
	return content
}

func updateChartYAML(content, newVersion, snapshot string) string {
	content = regexp.MustCompile(`(?m)^appVersion: `+semverCore).ReplaceAllString(content, "appVersion: "+newVersion)
	content = regexp.MustCompile(`(?m)^version: `+semverCore+`(?:-SNAPSHOT)?`).ReplaceAllString(content, "version: "+snapshot)
	return content
}

func updateHelmAgentValues(content, newVersion, snapshot string) string {
	lines := strings.Split(content, "\n")
	inAgent := false
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "agent:" {
			inAgent = true
			continue
		}
		if inAgent {
			if trimmed != "" && !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") {
				inAgent = false
				continue
			}
			if strings.HasPrefix(line, "  version:") {
				lines[i] = "  version: " + newVersion
				continue
			}
			if strings.Contains(line, "tag:") {
				lines[i] = regexp.MustCompile(`tag: "[^"]+"`).ReplaceAllString(line, `tag: "`+snapshot+`"`)
			}
		}
	}
	return strings.Join(lines, "\n")
}

func updateEdotCollectorValues(content, newVersion string) string {
	re := regexp.MustCompile(`(tag: ")` + semverCore + `(")`)
	return re.ReplaceAllString(content, `${1}`+newVersion+`${2}`)
}
