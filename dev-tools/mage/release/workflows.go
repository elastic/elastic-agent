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

var releasePRLabels = []string{"release", "Team:Automation", "skip-changelog"}

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

// RunPatchRelease updates version and docs on the release branch.
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
	if err := repo.EnsureBranch(releaseBranch); err != nil {
		return err
	}

	if err := UpdateVersion(cfg.CurrentRelease); err != nil {
		return err
	}
	if err := UpdateDocs(cfg.CurrentRelease); err != nil {
		return err
	}

	commitMsg := fmt.Sprintf("[Release] Prepare patch release %s", cfg.CurrentRelease)
	committed, err := repo.CommitAll(commitMsg, cfg.GitAuthorName, cfg.GitAuthorEmail)
	if err != nil {
		return err
	}

	if cfg.DryRun {
		fmt.Println("\nDRY RUN: Skipping push")
		fmt.Printf("Branch prepared: %s\n", releaseBranch)
		if committed {
			fmt.Println("Review changes with 'git diff'")
		}
		return nil
	}

	if !committed {
		fmt.Println("No changes to push")
		return nil
	}

	if err := repo.Push("origin"); err != nil {
		return err
	}

	fmt.Printf("\n=== Patch Release Workflow Complete ===\n")
	fmt.Printf("Changes pushed to branch %s\n", releaseBranch)

	return nil
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
- Updated documentation and K8s manifests
- Added backport rule to .mergify.yml

### Checklist
- [ ] Verify version is correct in version/version.go
- [ ] Check K8s manifests have correct image tags
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
