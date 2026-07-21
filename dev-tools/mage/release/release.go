// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package release

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"golang.org/x/sys/execabs"
)

var defaultBeatVersionPattern = regexp.MustCompile(`const defaultBeatVersion = "([^"]+)"`)

// ReadAgentVersion returns defaultBeatVersion from version/version.go.
func ReadAgentVersion() (string, error) {
	versionFile := "version/version.go"
	content, err := os.ReadFile(versionFile)
	if err != nil {
		return "", fmt.Errorf("failed to read %s: %w", versionFile, err)
	}
	match := defaultBeatVersionPattern.FindSubmatch(content)
	if match == nil {
		return "", fmt.Errorf("version pattern not found in %s", versionFile)
	}
	return string(match[1]), nil
}

func validateRepoRelativePath(path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("path must not be empty")
	}
	if filepath.IsAbs(path) {
		return "", fmt.Errorf("absolute path not allowed: %s", path)
	}

	cleaned := filepath.Clean(path)
	if cleaned == ".." || strings.HasPrefix(cleaned, ".."+string(os.PathSeparator)) {
		return "", fmt.Errorf("path escapes repository root: %s", path)
	}

	return cleaned, nil
}

func writeRepoFile(relPath string, content []byte) error {
	safePath, err := validateRepoRelativePath(relPath)
	if err != nil {
		return err
	}

	if !isReleaseWritablePath(safePath) {
		return fmt.Errorf("unsupported file path: %s", relPath)
	}

	return os.WriteFile(safePath, content, 0644) //nolint:gosec // safePath is validated and allowlisted for release automation files
}

// DocsUpdateOptions configures documentation and manifest updates.
// Mirrors ingest-dev release_scripts/elastic-agent.mak update-docs (BASE/CURRENT/RELEASE).
type DocsUpdateOptions struct {
	BaseBranch     string
	CurrentVersion string
	ReleaseBranch  string
	DocBranch      string // if empty, inferred per workflow
}

// UpdateVersion updates the version in version/version.go.
func UpdateVersion(newVersion string) error {
	versionFile, err := validateRepoRelativePath("version/version.go")
	if err != nil {
		return err
	}

	content, err := os.ReadFile(versionFile)
	if err != nil {
		return fmt.Errorf("failed to read %s: %w", versionFile, err)
	}

	re := regexp.MustCompile(`(const\s+defaultBeatVersion\s*=\s*)"[^"]+"`)
	newContent := re.ReplaceAllString(string(content), `${1}"`+newVersion+`"`)

	if newContent == string(content) {
		versionRe := regexp.MustCompile(`const\s+defaultBeatVersion\s*=\s*"([^"]+)"`)
		matches := versionRe.FindStringSubmatch(string(content))
		if len(matches) >= 2 && matches[1] == newVersion {
			fmt.Printf("Version already set to %s in %s\n", newVersion, versionFile)
			return nil
		}
		return fmt.Errorf("version pattern not found in %s", versionFile)
	}

	err = writeRepoFile(versionFile, []byte(newContent))
	if err != nil {
		return fmt.Errorf("failed to write %s: %w", versionFile, err)
	}

	fmt.Printf("Updated version to %s in %s\n", newVersion, versionFile)
	return nil
}

const versionAsciidocPath = "version/docs/version.asciidoc"

// UpdatePatchDocs updates :stack-version: in version/docs/version.asciidoc for patch releases.
func UpdatePatchDocs(newVersion string) error {
	safePath, err := validateRepoRelativePath(versionAsciidocPath)
	if err != nil {
		return err
	}

	content, err := os.ReadFile(safePath)
	if err != nil {
		return fmt.Errorf("failed to read %s: %w", safePath, err)
	}

	re := regexp.MustCompile(`(:stack-version:\s*)` + semverCore)
	newContent := re.ReplaceAllString(string(content), `${1}`+newVersion)
	if newContent == string(content) {
		stackVersionRe := regexp.MustCompile(`:stack-version:\s*(` + semverCore + `)`)
		matches := stackVersionRe.FindStringSubmatch(string(content))
		if len(matches) >= 2 && matches[1] == newVersion {
			fmt.Printf("Stack version already set to %s in %s\n", newVersion, safePath)
			return nil
		}
		return fmt.Errorf("stack-version pattern not found in %s", safePath)
	}

	if err := writeRepoFile(safePath, []byte(newContent)); err != nil {
		return fmt.Errorf("failed to write %s: %w", safePath, err)
	}

	fmt.Printf("Updated stack version to %s in %s\n", newVersion, safePath)
	return nil
}

// UpdateDocs updates version references using release-branch defaults.
func UpdateDocs(newVersion string) error {
	releaseBranch := inferReleaseBranch(newVersion)
	return UpdateDocsWithOptions(DocsUpdateOptions{
		BaseBranch:     releaseBranch,
		CurrentVersion: newVersion,
		ReleaseBranch:  releaseBranch,
	})
}

// UpdateDocsWithOptions updates asciidoc, K8s/Helm manifests, and docs URLs.
// Mirrors ingest-dev elastic-agent.mak update-docs.
func UpdateDocsWithOptions(opts DocsUpdateOptions) error {
	if opts.CurrentVersion == "" {
		return fmt.Errorf("CurrentVersion is required")
	}
	if opts.ReleaseBranch == "" {
		opts.ReleaseBranch = inferReleaseBranch(opts.CurrentVersion)
	}
	if opts.BaseBranch == "" {
		opts.BaseBranch = opts.ReleaseBranch
	}

	docBranch := opts.DocBranch
	if docBranch == "" {
		docBranch = opts.BaseBranch
		if docBranch == "main" || docBranch == "current" {
			docBranch = opts.ReleaseBranch
		}
	}

	if err := updateAsciidocVersion(opts.CurrentVersion, docBranch); err != nil {
		return err
	}

	files, err := collectDocFiles()
	if err != nil {
		return err
	}
	for _, file := range files {
		if err := updateVersionInFile(file, opts.CurrentVersion); err != nil {
			return err
		}
	}

	if err := rewriteBranchRefs("deploy/kubernetes/elastic-agent-standalone-kubernetes.yaml", opts.BaseBranch, opts.ReleaseBranch); err != nil {
		return err
	}
	if err := rewriteBranchRefs("README.md", opts.BaseBranch, opts.ReleaseBranch); err != nil {
		return err
	}

	fmt.Printf("Updated documentation files to version %s\n", opts.CurrentVersion)
	return nil
}

func updateAsciidocVersion(currentVersion, docBranch string) error {
	safePath, err := validateRepoRelativePath(versionAsciidocPath)
	if err != nil {
		return err
	}

	content, err := os.ReadFile(safePath)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Printf("Skipping missing file %s\n", safePath)
			return nil
		}
		return fmt.Errorf("failed to read %s: %w", safePath, err)
	}

	newContent := string(content)
	newContent = regexp.MustCompile(`(:stack-version:\s*)`+semverCore).ReplaceAllString(newContent, `${1}`+currentVersion)
	newContent = regexp.MustCompile(`(:doc-branch:\s*)\S+`).ReplaceAllString(newContent, `${1}`+docBranch)

	if newContent == string(content) {
		fmt.Printf("No asciidoc version changes needed in %s\n", safePath)
		return nil
	}

	if err := writeRepoFile(safePath, []byte(newContent)); err != nil {
		return fmt.Errorf("failed to write %s: %w", safePath, err)
	}
	fmt.Printf("Updated asciidoc version refs in %s\n", safePath)
	return nil
}

func rewriteBranchRefs(relPath, baseBranch, releaseBranch string) error {
	if baseBranch == "" || releaseBranch == "" || baseBranch == releaseBranch {
		return nil
	}

	safePath, err := validateRepoRelativePath(relPath)
	if err != nil {
		return err
	}

	content, err := os.ReadFile(safePath)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Printf("Skipping missing file %s\n", safePath)
			return nil
		}
		return fmt.Errorf("failed to read %s: %w", safePath, err)
	}

	var newContent string
	switch safePath {
	case "README.md":
		re := regexp.MustCompile(regexp.QuoteMeta("/" + baseBranch + "/"))
		newContent = re.ReplaceAllString(string(content), "/"+releaseBranch+"/")
	default:
		re := regexp.MustCompile(regexp.QuoteMeta(baseBranch))
		newContent = re.ReplaceAllString(string(content), releaseBranch)
	}

	if newContent == string(content) {
		fmt.Printf("No branch ref changes needed in %s\n", safePath)
		return nil
	}

	if err := writeRepoFile(safePath, []byte(newContent)); err != nil {
		return fmt.Errorf("failed to write %s: %w", safePath, err)
	}
	fmt.Printf("Updated branch refs in %s (%s → %s)\n", safePath, baseBranch, releaseBranch)
	return nil
}

func updateVersionInFile(filePath, newVersion string) error {
	safePath, err := validateRepoRelativePath(filePath)
	if err != nil {
		return err
	}

	content, err := os.ReadFile(safePath)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Printf("Skipping missing file %s\n", safePath)
			return nil
		}
		return fmt.Errorf("failed to read %s: %w", safePath, err)
	}

	newContent := applyVersionReplacements(safePath, string(content), newVersion)
	if newContent == string(content) {
		fmt.Printf("No version changes needed in %s\n", safePath)
		return nil
	}

	err = writeRepoFile(safePath, []byte(newContent))
	if err != nil {
		return fmt.Errorf("failed to write %s: %w", safePath, err)
	}

	fmt.Printf("Updated version to %s in %s\n", newVersion, safePath)
	return nil
}

// RunMageUpdate runs 'mage update' in the repository (elastic-agent.mak update-project).
func RunMageUpdate() error {
	return runMageUpdate()
}

// runMageUpdate is the default implementation; tests may replace it.
var runMageUpdate = func() error {
	fmt.Println("Running 'mage update'...")
	ctx := context.Background()
	cmd := execabs.CommandContext(ctx, "mage", "update")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("mage update failed: %w", err)
	}
	fmt.Println("Completed 'mage update'")
	return nil
}

// PrepareMajorMinorRelease updates version, docs, and mergify for a major/minor release.
func PrepareMajorMinorRelease(cfg *ReleaseConfig) error {
	fmt.Printf("=== Preparing Major/Minor Release %s ===\n", cfg.CurrentRelease)

	if err := UpdateVersion(cfg.CurrentRelease); err != nil {
		return err
	}
	if err := UpdateDocsWithOptions(DocsUpdateOptions{
		BaseBranch:     cfg.BaseBranch,
		CurrentVersion: cfg.CurrentRelease,
		ReleaseBranch:  cfg.ReleaseBranch,
	}); err != nil {
		return err
	}
	if err := UpdateMergify(cfg.CurrentRelease); err != nil {
		return err
	}

	fmt.Println("All files updated for major/minor release")
	return nil
}
