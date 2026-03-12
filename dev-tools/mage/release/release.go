// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package release

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// UpdateVersion updates the version in version/version.go
func UpdateVersion(newVersion string) error {
	versionFile := "version/version.go"

	content, err := os.ReadFile(versionFile)
	if err != nil {
		return fmt.Errorf("failed to read %s: %w", versionFile, err)
	}

	// Replace the version string
	// Pattern: const defaultBeatVersion = "X.Y.Z"
	re := regexp.MustCompile(`(const\s+defaultBeatVersion\s*=\s*)"[^"]+"`)
	newContent := re.ReplaceAllString(string(content), `${1}"`+newVersion+`"`)

	if newContent == string(content) {
		return fmt.Errorf("version pattern not found in %s", versionFile)
	}

	err = os.WriteFile(versionFile, []byte(newContent), 0644)
	if err != nil {
		return fmt.Errorf("failed to write %s: %w", versionFile, err)
	}

	fmt.Printf("✓ Updated version to %s in %s\n", newVersion, versionFile)
	return nil
}

// UpdateDocs updates version references in documentation and K8s manifests
func UpdateDocs(newVersion string) error {
	// Update K8s manifests
	k8sFiles := []string{
		"deploy/kubernetes/elastic-agent-managed-kubernetes.yaml",
		"deploy/kubernetes/elastic-agent-standalone-kubernetes.yaml",
	}

	for _, file := range k8sFiles {
		if err := updateVersionInFile(file, newVersion); err != nil {
			return err
		}
	}

	return nil
}

// updateVersionInFile updates version references in a file
func updateVersionInFile(filePath, newVersion string) error {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read %s: %w", filePath, err)
	}

	// Pattern: docker.elastic.co/elastic-agent/elastic-agent:X.Y.Z
	re := regexp.MustCompile(`(docker\.elastic\.co/elastic-agent/elastic-agent:)[0-9]+\.[0-9]+\.[0-9]+`)
	newContent := re.ReplaceAllString(string(content), `${1}`+newVersion)

	if newContent == string(content) {
		// No changes needed
		fmt.Printf("  No version changes needed in %s\n", filePath)
		return nil
	}

	err = os.WriteFile(filePath, []byte(newContent), 0644)
	if err != nil {
		return fmt.Errorf("failed to write %s: %w", filePath, err)
	}

	fmt.Printf("✓ Updated version to %s in %s\n", newVersion, filePath)
	return nil
}

// UpdateMergify adds a new backport rule to .mergify.yml
func UpdateMergify(version string) error {
	mergifyFile := ".mergify.yml"

	// Read the YAML file
	content, err := os.ReadFile(mergifyFile)
	if err != nil {
		return fmt.Errorf("failed to read %s: %w", mergifyFile, err)
	}

	var config map[string]interface{}
	if err := yaml.Unmarshal(content, &config); err != nil {
		return fmt.Errorf("failed to parse %s: %w", mergifyFile, err)
	}

	// Extract major.minor from version (e.g., "9.4.0" -> "9.4")
	parts := strings.Split(version, ".")
	if len(parts) < 2 {
		return fmt.Errorf("invalid version format: %s (expected X.Y.Z)", version)
	}
	branchVersion := fmt.Sprintf("%s.%s", parts[0], parts[1])

	// Get pull_request_rules array
	rules, ok := config["pull_request_rules"].([]interface{})
	if !ok {
		return fmt.Errorf("pull_request_rules not found or invalid format")
	}

	// Check if rule already exists
	label := fmt.Sprintf("backport-%s", branchVersion)
	for _, rule := range rules {
		ruleMap, ok := rule.(map[string]interface{})
		if !ok {
			continue
		}
		name, ok := ruleMap["name"].(string)
		if ok && strings.Contains(name, branchVersion) {
			fmt.Printf("  Backport rule for %s already exists\n", branchVersion)
			return nil
		}
	}

	// Create new backport rule
	newRule := map[string]interface{}{
		"name": fmt.Sprintf("backport patches to %s branch", branchVersion),
		"conditions": []interface{}{
			"merged",
			fmt.Sprintf("label=%s", label),
		},
		"actions": map[string]interface{}{
			"backport": map[string]interface{}{
				"branches": []interface{}{branchVersion},
			},
		},
	}

	// Add the new rule to the end of pull_request_rules
	rules = append(rules, newRule)
	config["pull_request_rules"] = rules

	// Marshal back to YAML
	output, err := yaml.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal YAML: %w", err)
	}

	// Write back to file
	err = os.WriteFile(mergifyFile, output, 0644)
	if err != nil {
		return fmt.Errorf("failed to write %s: %w", mergifyFile, err)
	}

	fmt.Printf("✓ Added backport rule for %s to %s\n", branchVersion, mergifyFile)
	return nil
}

// ReleaseConfig holds configuration for release operations
type ReleaseConfig struct {
	Version       string
	BaseBranch    string
	ReleaseBranch string
	Owner         string
	Repo          string
	AuthorName    string
	AuthorEmail   string
}

// LoadReleaseConfigFromEnv loads release configuration from environment variables
func LoadReleaseConfigFromEnv() (*ReleaseConfig, error) {
	version := os.Getenv("CURRENT_RELEASE")
	if version == "" {
		return nil, fmt.Errorf("CURRENT_RELEASE environment variable not set")
	}

	baseBranch := os.Getenv("BASE_BRANCH")
	if baseBranch == "" {
		baseBranch = "main"
	}

	// Extract major.minor for release branch (e.g., "9.4.0" -> "9.4")
	parts := strings.Split(version, ".")
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid version format: %s", version)
	}
	releaseBranch := fmt.Sprintf("%s.%s", parts[0], parts[1])

	owner := os.Getenv("PROJECT_OWNER")
	if owner == "" {
		owner = "elastic"
	}

	repo := os.Getenv("PROJECT_REPO")
	if repo == "" {
		repo = "elastic-agent"
	}

	authorName := os.Getenv("GIT_AUTHOR_NAME")
	if authorName == "" {
		authorName = "elastic-machine"
	}

	authorEmail := os.Getenv("GIT_AUTHOR_EMAIL")
	if authorEmail == "" {
		authorEmail = "infra-root+elasticmachine@elastic.co"
	}

	return &ReleaseConfig{
		Version:       version,
		BaseBranch:    baseBranch,
		ReleaseBranch: releaseBranch,
		Owner:         owner,
		Repo:          repo,
		AuthorName:    authorName,
		AuthorEmail:   authorEmail,
	}, nil
}

// PrepareMajorMinorRelease prepares files for a major/minor release
func PrepareMajorMinorRelease(cfg *ReleaseConfig) error {
	fmt.Printf("=== Preparing Major/Minor Release %s ===\n", cfg.Version)

	// Update version files
	if err := UpdateVersion(cfg.Version); err != nil {
		return err
	}

	// Update documentation
	if err := UpdateDocs(cfg.Version); err != nil {
		return err
	}

	// Update mergify config
	if err := UpdateMergify(cfg.Version); err != nil {
		return err
	}

	fmt.Println("✓ All files updated for major/minor release")
	return nil
}

// CreateReleaseBranch creates a release branch and commits changes
func CreateReleaseBranch(cfg *ReleaseConfig, repoPath string) error {
	fmt.Printf("=== Creating Release Branch %s ===\n", cfg.ReleaseBranch)

	// Open the repository
	gitRepo, err := OpenRepo(repoPath)
	if err != nil {
		return err
	}

	// Create the release branch
	if err := gitRepo.CreateBranch(cfg.ReleaseBranch); err != nil {
		return err
	}

	// Commit all changes
	commitMsg := fmt.Sprintf("[Release] Prepare release %s", cfg.Version)
	if err := gitRepo.CommitAll(commitMsg, cfg.AuthorName, cfg.AuthorEmail); err != nil {
		return err
	}

	fmt.Printf("✓ Created release branch %s with changes\n", cfg.ReleaseBranch)
	return nil
}

// CreateReleasePR creates a pull request for the release
func CreateReleasePR(cfg *ReleaseConfig, ghClient *GitHubClient) error {
	fmt.Printf("=== Creating Release PR ===\n")

	prBody := fmt.Sprintf(`## Release %s

### Changes
- Updated version to %s
- Updated documentation and K8s manifests
- Added backport rule to .mergify.yml

### Checklist
- [ ] Verify version is correct in version/version.go
- [ ] Check K8s manifests have correct image tags
- [ ] Confirm mergify config is updated
- [ ] Run integration tests

---
🤖 This PR was created by the release automation system.
`, cfg.Version, cfg.Version)

	prOpts := PROptions{
		Owner:       cfg.Owner,
		Repo:        cfg.Repo,
		Title:       fmt.Sprintf("[Release %s] Prepare release branch", cfg.Version),
		Head:        cfg.ReleaseBranch,
		Base:        cfg.BaseBranch,
		Body:        prBody,
		Draft:       false,
		Maintainers: true,
	}

	pr, err := ghClient.CreatePR(prOpts)
	if err != nil {
		return err
	}

	fmt.Printf("✓ Created PR: %s\n", pr.GetHTMLURL())
	return nil
}
