// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package release

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

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

// UpdateDocs updates version references in K8s manifests, Helm charts, and kustomize files.
func UpdateDocs(newVersion string) error {
	files, err := collectDocFiles()
	if err != nil {
		return err
	}

	for _, file := range files {
		if err := updateVersionInFile(file, newVersion); err != nil {
			return err
		}
	}

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

// PrepareMajorMinorRelease updates version, docs, and mergify for a major/minor release.
func PrepareMajorMinorRelease(cfg *ReleaseConfig) error {
	fmt.Printf("=== Preparing Major/Minor Release %s ===\n", cfg.CurrentRelease)

	if err := UpdateVersion(cfg.CurrentRelease); err != nil {
		return err
	}
	if err := UpdateDocs(cfg.CurrentRelease); err != nil {
		return err
	}
	if err := UpdateMergify(cfg.CurrentRelease); err != nil {
		return err
	}

	fmt.Println("All files updated for major/minor release")
	return nil
}
