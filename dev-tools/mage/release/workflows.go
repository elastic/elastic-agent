// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package release

import (
	"fmt"
	"os"
	"strings"

	"github.com/google/go-github/v68/github"
)

var releasePRLabels = []string{"backport-skip", "skip-changelog"}

var patchVersionPRLabels = []string{"Team:Automation", "release", "skip-changelog"}

var patchDocsPRLabels = []string{"Team:Automation", "release", "docs", "in progress", "skip-changelog"}

func checkRequirements(cfg *ReleaseConfig) error {
	parts := strings.Split(cfg.CurrentRelease, ".")
	if len(parts) < 2 {
		return fmt.Errorf("invalid version format: %s", cfg.CurrentRelease)
	}

	repo, err := OpenRepo(".")
	if err != nil {
		return err
	}

	clean, err := repo.IsClean()
	if err != nil {
		return err
	}
	if !clean {
		return fmt.Errorf("working directory is not clean. Please commit or stash changes first")
	}

	return nil
}

// RunMajorMinorRelease creates the release branch from main and opens a PR with release updates.
func RunMajorMinorRelease(cfg *ReleaseConfig) error {
	fmt.Println("=== Starting Major/Minor Release Workflow ===")

	if err := cfg.Validate(); err != nil {
		return err
	}
	if err := checkRequirements(cfg); err != nil {
		return err
	}

	repo, err := OpenRepo(".")
	if err != nil {
		return err
	}

	fmt.Printf("Creating release branch: %s from %s\n", cfg.ReleaseBranch, cfg.BaseBranch)
	if err := repo.EnsureBranchFrom(cfg.BaseBranch, cfg.ReleaseBranch); err != nil {
		return err
	}

	if err := PrepareMajorMinorRelease(cfg); err != nil {
		return err
	}

	commitMsg := fmt.Sprintf("[Release] Prepare release %s", cfg.CurrentRelease)
	_, err = repo.CommitAll(commitMsg, cfg.GitAuthorName, cfg.GitAuthorEmail)
	if err != nil {
		return err
	}

	prOpts := PROptions{
		Owner:     cfg.ProjectOwner,
		Repo:      cfg.ProjectRepo,
		Title:     fmt.Sprintf("[Release %s] Prepare release branch", cfg.CurrentRelease),
		Head:      cfg.ReleaseBranch,
		Base:      cfg.BaseBranch,
		Body:      majorMinorPRBody(cfg.CurrentRelease),
		Reviewers: cfg.ProjectReviewers,
		Labels:    releasePRLabels,
	}

	if cfg.DryRun {
		fmt.Println("\nDRY RUN: Skipping push and PR creation")
		fmt.Printf("Release branch prepared: %s\n", cfg.ReleaseBranch)
		fmt.Println("Review changes with 'git diff'")
		return nil
	}

	pr, err := finalizePR(repo, NewGitHubClient(cfg.GitHubToken), cfg.ReleaseBranch, cfg.BaseBranch, prOpts)
	if err != nil {
		return err
	}

	fmt.Printf("\n=== Major/Minor Release Workflow Complete ===\n")
	fmt.Printf("Release branch created: %s\n", cfg.ReleaseBranch)
	if pr != nil {
		fmt.Printf("PR: %s\n", pr.GetHTMLURL())
	} else {
		fmt.Println("No PR created (release already up to date)")
	}

	return nil
}

// RunPatchRelease opens two PRs into the release branch: a version bump and a docs-only update.
func RunPatchRelease(cfg *ReleaseConfig) error {
	fmt.Println("=== Starting Patch Release Workflow ===")

	if err := cfg.Validate(); err != nil {
		return err
	}
	if err := checkRequirements(cfg); err != nil {
		return err
	}

	repo, err := OpenRepo(".")
	if err != nil {
		return err
	}

	releaseBranch := cfg.ReleaseBranch
	if releaseBranch == "" {
		releaseBranch = inferReleaseBranch(cfg.CurrentRelease)
	}

	fmt.Printf("Using release branch: %s\n", releaseBranch)

	gh := NewGitHubClient(cfg.GitHubToken)

	fmt.Println("--- Creating PR 1: Version bump ---")
	versionPR, err := createPatchReleasePR(repo, gh, cfg, releaseBranch, patchVersionBranchName(cfg.CurrentRelease), func() error {
		if err := UpdateVersion(cfg.CurrentRelease); err != nil {
			return err
		}
		return UpdateDocs(cfg.CurrentRelease)
	}, fmt.Sprintf("update version to %s", cfg.CurrentRelease), PROptions{
		Owner:     cfg.ProjectOwner,
		Repo:      cfg.ProjectRepo,
		Title:     fmt.Sprintf("[Release] Update version to %s", cfg.CurrentRelease),
		Head:      patchVersionBranchName(cfg.CurrentRelease),
		Base:      releaseBranch,
		Body:      patchVersionPRBody(cfg.CurrentRelease, cfg.LatestRelease),
		Reviewers: cfg.ProjectReviewers,
		Labels:    patchVersionPRLabels,
	})
	if err != nil {
		return err
	}

	fmt.Println("--- Creating PR 2: Docs ---")
	docsPR, err := createPatchReleasePR(repo, gh, cfg, releaseBranch, patchDocsBranchName(cfg.CurrentRelease), func() error {
		return UpdatePatchDocs(cfg.CurrentRelease)
	}, fmt.Sprintf("update docs version %s", cfg.CurrentRelease), PROptions{
		Owner:     cfg.ProjectOwner,
		Repo:      cfg.ProjectRepo,
		Title:     fmt.Sprintf("docs: update docs versions %s", cfg.CurrentRelease),
		Head:      patchDocsBranchName(cfg.CurrentRelease),
		Base:      releaseBranch,
		Body:      patchReleasePRBody(cfg.CurrentRelease),
		Reviewers: cfg.ProjectReviewers,
		Labels:    patchDocsPRLabels,
	})
	if err != nil {
		return err
	}

	fmt.Printf("\n=== Patch Release Workflow Complete ===\n")
	if versionPR != nil {
		fmt.Printf("PR 1 (version): %s\n", versionPR.GetHTMLURL())
	} else {
		fmt.Println("PR 1 (version): not created (already up to date)")
	}
	if docsPR != nil {
		fmt.Printf("PR 2 (docs): %s\n", docsPR.GetHTMLURL())
	} else {
		fmt.Println("PR 2 (docs): not created (already up to date)")
	}

	return nil
}

func createPatchReleasePR(repo *GitRepo, gh *GitHubClient, cfg *ReleaseConfig, releaseBranch, branchName string, prepare func() error, commitMsg string, prOpts PROptions) (*github.PullRequest, error) {
	fmt.Printf("Creating branch: %s from %s\n", branchName, releaseBranch)
	if err := repo.EnsureBranchFrom(releaseBranch, branchName); err != nil {
		return nil, err
	}

	if err := prepare(); err != nil {
		return nil, err
	}

	committed, err := repo.CommitAll(commitMsg, cfg.GitAuthorName, cfg.GitAuthorEmail)
	if err != nil {
		return nil, err
	}

	if cfg.DryRun {
		fmt.Printf("DRY RUN: Branch prepared: %s\n", branchName)
		if committed {
			fmt.Println("Review changes with 'git diff'")
		}
		return nil, nil
	}

	if !committed {
		fmt.Printf("No new changes on %s; checking for existing PR\n", branchName)
	}

	return finalizePR(repo, gh, branchName, releaseBranch, prOpts)
}

func patchVersionBranchName(version string) string {
	return fmt.Sprintf("update-version-next-%s", version)
}

func patchDocsBranchName(version string) string {
	return fmt.Sprintf("update-docs-version-%s", version)
}

func patchVersionPRBody(current, previous string) string {
	if previous == "" {
		return fmt.Sprintf("Updates references to the new release %s.", current)
	}
	return fmt.Sprintf("Updates references to the new release %s.\n\nMerge after the release %s.", current, previous)
}

func patchReleasePRBody(version string) string {
	return fmt.Sprintf(`Updates docs versions to %s.

Merge before the final Release build.
`, version)
}

// CreateReleaseBranch creates the release branch from main and commits prepared changes.
func CreateReleaseBranch(cfg *ReleaseConfig, repoPath string) error {
	fmt.Printf("=== Creating Release Branch %s ===\n", cfg.ReleaseBranch)

	originalWd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to get working directory: %w", err)
	}
	if err := os.Chdir(repoPath); err != nil {
		return fmt.Errorf("failed to change to repository path %s: %w", repoPath, err)
	}
	defer func() {
		_ = os.Chdir(originalWd)
	}()

	gitRepo, err := OpenRepo(".")
	if err != nil {
		return err
	}

	if err := gitRepo.EnsureBranchFrom(cfg.BaseBranch, cfg.ReleaseBranch); err != nil {
		return err
	}

	if err := PrepareMajorMinorRelease(cfg); err != nil {
		return err
	}

	commitMsg := fmt.Sprintf("[Release] Prepare release %s", cfg.CurrentRelease)
	if _, err := gitRepo.CommitAll(commitMsg, cfg.GitAuthorName, cfg.GitAuthorEmail); err != nil {
		return err
	}

	fmt.Printf("Created release branch %s with changes\n", cfg.ReleaseBranch)
	return nil
}

// CreateReleasePR creates a pull request for the release branch.
func CreateReleasePR(cfg *ReleaseConfig, ghClient *GitHubClient) error {
	fmt.Println("=== Creating Release PR ===")

	prOpts := PROptions{
		Owner:     cfg.ProjectOwner,
		Repo:      cfg.ProjectRepo,
		Title:     fmt.Sprintf("[Release %s] Prepare release branch", cfg.CurrentRelease),
		Head:      cfg.ReleaseBranch,
		Base:      cfg.BaseBranch,
		Body:      majorMinorPRBody(cfg.CurrentRelease),
		Reviewers: cfg.ProjectReviewers,
		Labels:    releasePRLabels,
	}

	repo, err := OpenRepo(".")
	if err != nil {
		return err
	}

	pr, err := finalizePR(repo, ghClient, cfg.ReleaseBranch, cfg.BaseBranch, prOpts)
	if err != nil {
		return err
	}
	if pr == nil {
		fmt.Println("No PR created (release already up to date)")
		return nil
	}

	fmt.Printf("Created PR: %s\n", pr.GetHTMLURL())
	return nil
}

func majorMinorPRBody(version string) string {
	return fmt.Sprintf(`## Release %s

### Changes
- Updated version to %s
- Updated K8s manifests, Helm charts, kustomize overlays, and integration testdata
- Added backport rule to .mergify.yml

### Checklist
- [ ] Verify version is correct in version/version.go
- [ ] Check K8s manifests and Helm examples have correct image tags
- [ ] Confirm mergify config is updated
- [ ] Run integration tests
`, version, version)
}

func finalizePR(repo *GitRepo, gh *GitHubClient, branchName, baseBranch string, opts PROptions) (*github.PullRequest, error) {
	if err := repo.CheckoutBranch(branchName); err != nil {
		return nil, err
	}

	existingPR, found, err := gh.FindOpenPR(opts.Owner, opts.Repo, opts.Head, opts.Base)
	if err != nil {
		return nil, err
	}
	if found {
		gh.ensurePRLabels(opts.Owner, opts.Repo, existingPR.GetNumber(), opts.Labels)
		return existingPR, nil
	}

	ahead, err := repo.HasCommitsAheadOf(baseBranch)
	if err != nil {
		return nil, err
	}
	if !ahead {
		fmt.Printf("No new commits on %s compared to %s; skipping push and PR creation\n", branchName, baseBranch)
		return nil, nil
	}

	if err := repo.Push("origin"); err != nil {
		return nil, err
	}

	return gh.CreatePR(opts)
}
