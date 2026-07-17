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

// PR label sets match elastic-vault-github-plugin-prod release PRs.
var (
	releasePRLabels   = []string{"release", "Team:Automation", "skip-changelog"}
	patchDocsPRLabels = []string{"docs", "in progress", "release", "Team:Automation", "skip-changelog"}
	ffReleasePRLabels = []string{"release", "docs", "in progress", "Team:Automation", "skip-changelog"}
)

// Feature-freeze merge-timing labels (number = RM merge order).
const (
	mergeLabelFFDay        = "merge:1-ff-day"
	mergeLabelAfterBranch  = "merge:2-after-branch"
	mergeLabelAfterImages  = "merge:3-after-images"
	mergeLabelAfterRelease = "merge:4-after-release"
)

// Patch-release merge-timing labels.
const (
	mergeLabelBeforeBuild = "merge:1-before-build"
)

func backportLabel(releaseBranch string) string {
	return fmt.Sprintf("backport-%s", releaseBranch)
}

func prAMainLabels(releaseBranch string) []string {
	return []string{"release", "impact:critical", backportLabel(releaseBranch), "skip-changelog", "Team:Automation", mergeLabelFFDay}
}

func prBReleaseLabels() []string {
	return append(append([]string{}, ffReleasePRLabels...), mergeLabelAfterBranch)
}

func prCMainLabels(releaseBranch string) []string {
	return []string{"release", "docs", "in progress", backportLabel(releaseBranch), "skip-changelog", "Team:Automation", mergeLabelAfterImages}
}

func prDNextPatchLabels() []string {
	return append(append([]string{}, releasePRLabels...), mergeLabelAfterRelease)
}

func patchVersionPRLabels() []string {
	return append(append([]string{}, releasePRLabels...), mergeLabelBeforeBuild)
}

func patchDocsPRLabelsWithMerge() []string {
	return append(append([]string{}, patchDocsPRLabels...), mergeLabelBeforeBuild)
}

func checkRequirements(cfg *ReleaseConfig) error {
	parts := strings.Split(cfg.CurrentRelease, ".")
	if len(parts) < 2 {
		return fmt.Errorf("invalid version format: %s", cfg.CurrentRelease)
	}

	major := parts[0]
	patch := ""
	if len(parts) >= 3 {
		patch = parts[2]
	}
	if (major == "6" || major == "7" || major == "8") && patch == "0" {
		return fmt.Errorf("minor releases for version %s.x are deprecated and blocked", major)
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

type workflowPR struct {
	branch string
	base   string
	opts   PROptions
}

// RunMajorMinorRelease executes the feature-freeze workflow:
// 1. Creates the release branch from BASE_BRANCH
// 2. Opens PR-A on main (backport rule + next minor version + manifests)
// 3. Opens PR-B on release branch (ff-release)
// 4. Opens PR-C on main (docs for next minor)
// 5. Opens PR-D on release branch (next patch prep)
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

	releaseBranch := cfg.ReleaseBranch

	fmt.Printf("Creating release branch: %s\n", releaseBranch)
	if err := repo.EnsureBranchFrom(cfg.BaseBranch, releaseBranch); err != nil {
		return err
	}

	prA, err := prepMainBackportAndVersion(repo, cfg)
	if err != nil {
		return err
	}
	prB, err := prepFFRelease(repo, cfg)
	if err != nil {
		return err
	}
	prC, err := prepMainDocs(repo, cfg)
	if err != nil {
		return err
	}
	prD, err := prepNextPatchOnReleaseBranch(repo, cfg)
	if err != nil {
		return err
	}

	branchesToFinalize := []workflowPR{prA, prB, prC, prD}

	if cfg.DryRun {
		fmt.Println("\nDRY RUN: Skipping push and PR creation")
		fmt.Printf("Release branch prepared: %s\n", releaseBranch)
		for _, item := range branchesToFinalize {
			fmt.Printf("Branch prepared: %s\n", item.branch)
		}
		return nil
	}

	if err := repo.CheckoutBranch(releaseBranch); err != nil {
		return err
	}
	if err := repo.Push("origin"); err != nil {
		return err
	}

	gh := NewGitHubClient(cfg.GitHubToken)
	var prs []*github.PullRequest
	for i, item := range branchesToFinalize {
		pr, err := finalizePR(repo, gh, item.branch, item.base, item.opts)
		if err != nil {
			return fmt.Errorf("failed to finalize PR %d/%d: %w", i+1, len(branchesToFinalize), err)
		}
		if pr != nil {
			prs = append(prs, pr)
		}
	}

	fmt.Printf("\n=== Major/Minor Release Workflow Complete ===\n")
	fmt.Printf("Release branch created: %s\n", releaseBranch)
	for i, pr := range prs {
		fmt.Printf("PR %d: %s\n", i+1, pr.GetHTMLURL())
	}
	if len(prs) == 0 {
		fmt.Println("No PRs created (release already up to date)")
	}

	return nil
}

func prepMainBackportAndVersion(repo *GitRepo, cfg *ReleaseConfig) (workflowPR, error) {
	branch := fmt.Sprintf("ff-prep-main-%s", cfg.CurrentRelease)
	fmt.Printf("\n--- Preparing PR-A: backport rule + version %s on %s ---\n", cfg.NextProjectMinorVersion, cfg.BaseBranch)

	if err := repo.EnsureBranchFrom(cfg.BaseBranch, branch); err != nil {
		return workflowPR{}, err
	}
	if err := UpdateMergify(cfg.ReleaseBranch); err != nil {
		return workflowPR{}, err
	}
	if err := UpdateVersion(cfg.NextProjectMinorVersion); err != nil {
		return workflowPR{}, err
	}
	// Match vault bump-version PRs that also refresh deployment manifests.
	if err := UpdateDocs(cfg.NextProjectMinorVersion); err != nil {
		return workflowPR{}, err
	}
	commitMsg := fmt.Sprintf("[Release] Prepare main for %s (backport + version %s)", cfg.CurrentRelease, cfg.NextProjectMinorVersion)
	if _, err := repo.CommitAll(commitMsg, cfg.GitAuthorName, cfg.GitAuthorEmail); err != nil {
		return workflowPR{}, err
	}

	return workflowPR{
		branch: branch,
		base:   cfg.BaseBranch,
		opts: PROptions{
			Owner:     cfg.ProjectOwner,
			Repo:      cfg.ProjectRepo,
			Title:     fmt.Sprintf("[Release] Prepare main for %s (backport + version %s)", cfg.CurrentRelease, cfg.NextProjectMinorVersion),
			Head:      branch,
			Base:      cfg.BaseBranch,
			Body:      prAMainBody(cfg),
			Reviewers: cfg.ProjectReviewers,
			Labels:    prAMainLabels(cfg.ReleaseBranch),
		},
	}, nil
}

func prepFFRelease(repo *GitRepo, cfg *ReleaseConfig) (workflowPR, error) {
	branch := fmt.Sprintf("ff-release-%s", cfg.CurrentRelease)
	fmt.Printf("\n--- Preparing PR-B: ff-release %s on %s ---\n", cfg.CurrentRelease, cfg.ReleaseBranch)

	if err := repo.EnsureBranchFrom(cfg.ReleaseBranch, branch); err != nil {
		return workflowPR{}, err
	}
	if err := UpdateVersion(cfg.CurrentRelease); err != nil {
		return workflowPR{}, err
	}
	if err := UpdateDocsWithOptions(DocsUpdateOptions{
		BaseBranch:     cfg.BaseBranch,
		CurrentVersion: cfg.CurrentRelease,
		ReleaseBranch:  cfg.ReleaseBranch,
	}); err != nil {
		return workflowPR{}, err
	}
	if err := runMageUpdate(); err != nil {
		return workflowPR{}, err
	}
	commitMsg := fmt.Sprintf("ff-release: update versions %s", cfg.CurrentRelease)
	if _, err := repo.CommitAll(commitMsg, cfg.GitAuthorName, cfg.GitAuthorEmail); err != nil {
		return workflowPR{}, err
	}

	return workflowPR{
		branch: branch,
		base:   cfg.ReleaseBranch,
		opts: PROptions{
			Owner:     cfg.ProjectOwner,
			Repo:      cfg.ProjectRepo,
			Title:     fmt.Sprintf("ff-release: update versions %s", cfg.CurrentRelease),
			Head:      branch,
			Base:      cfg.ReleaseBranch,
			Body:      prBReleaseBody(cfg),
			Reviewers: cfg.ProjectReviewers,
			Labels:    prBReleaseLabels(),
		},
	}, nil
}

func prepMainDocs(repo *GitRepo, cfg *ReleaseConfig) (workflowPR, error) {
	branch := fmt.Sprintf("ff-prep-main-docs-%s", cfg.NextProjectMinorVersion)
	fmt.Printf("\n--- Preparing PR-C: docs %s on %s ---\n", cfg.NextProjectMinorVersion, cfg.BaseBranch)

	if err := repo.EnsureBranchFrom(cfg.BaseBranch, branch); err != nil {
		return workflowPR{}, err
	}
	// elastic-agent.mak prepare-next-dev-minor: update-docs BASE=main CURRENT=next RELEASE=main
	if err := UpdateDocsWithOptions(DocsUpdateOptions{
		BaseBranch:     cfg.BaseBranch,
		CurrentVersion: cfg.NextProjectMinorVersion,
		ReleaseBranch:  cfg.BaseBranch,
		DocBranch:      "main",
	}); err != nil {
		return workflowPR{}, err
	}
	commitMsg := fmt.Sprintf("[Release] Update docs for %s", cfg.NextProjectMinorVersion)
	if _, err := repo.CommitAll(commitMsg, cfg.GitAuthorName, cfg.GitAuthorEmail); err != nil {
		return workflowPR{}, err
	}

	return workflowPR{
		branch: branch,
		base:   cfg.BaseBranch,
		opts: PROptions{
			Owner:     cfg.ProjectOwner,
			Repo:      cfg.ProjectRepo,
			Title:     fmt.Sprintf("[Release] Update docs for the %s release", cfg.NextProjectMinorVersion),
			Head:      branch,
			Base:      cfg.BaseBranch,
			Body:      prCMainBody(cfg),
			Reviewers: cfg.ProjectReviewers,
			Labels:    prCMainLabels(cfg.ReleaseBranch),
		},
	}, nil
}

func prepNextPatchOnReleaseBranch(repo *GitRepo, cfg *ReleaseConfig) (workflowPR, error) {
	branch := fmt.Sprintf("ff-prep-next-patch-%s", cfg.NextRelease)
	fmt.Printf("\n--- Preparing PR-D: next patch %s on %s ---\n", cfg.NextRelease, cfg.ReleaseBranch)

	if err := repo.EnsureBranchFrom(cfg.ReleaseBranch, branch); err != nil {
		return workflowPR{}, err
	}
	// elastic-agent.mak prepare-next-release: update-version (+ mage update when needed)
	if err := UpdateVersion(cfg.NextRelease); err != nil {
		return workflowPR{}, err
	}
	if err := runMageUpdate(); err != nil {
		return workflowPR{}, err
	}
	commitMsg := fmt.Sprintf("[Release] Update version to %s", cfg.NextRelease)
	if _, err := repo.CommitAll(commitMsg, cfg.GitAuthorName, cfg.GitAuthorEmail); err != nil {
		return workflowPR{}, err
	}

	return workflowPR{
		branch: branch,
		base:   cfg.ReleaseBranch,
		opts: PROptions{
			Owner:     cfg.ProjectOwner,
			Repo:      cfg.ProjectRepo,
			Title:     fmt.Sprintf("[Release] Update version to %s", cfg.NextRelease),
			Head:      branch,
			Base:      cfg.ReleaseBranch,
			Body:      prDNextPatchBody(cfg),
			Reviewers: cfg.ProjectReviewers,
			Labels:    prDNextPatchLabels(),
		},
	}, nil
}

func prAMainBody(cfg *ReleaseConfig) string {
	return fmt.Sprintf(`Prepares main for the %s feature freeze.

- Adds Mergify backport rule for branch %s (label %s)
- Bumps version/version.go to %s
- Refreshes deployment manifests for %s

Merge as soon as the %s branch is created.
`, cfg.CurrentRelease, cfg.ReleaseBranch, backportLabel(cfg.ReleaseBranch), cfg.NextProjectMinorVersion, cfg.NextProjectMinorVersion, cfg.ReleaseBranch)
}

func prBReleaseBody(cfg *ReleaseConfig) string {
	return fmt.Sprintf(`Feature-freeze release branch updates for %s.

Merge as soon as the %s branch exists.
`, cfg.CurrentRelease, cfg.ReleaseBranch)
}

func prCMainBody(cfg *ReleaseConfig) string {
	return fmt.Sprintf(`Updates documentation for the next minor %s.

Merge after the %s branch is created.
`, cfg.NextProjectMinorVersion, cfg.ReleaseBranch)
}

func prDNextPatchBody(cfg *ReleaseConfig) string {
	return fmt.Sprintf(`Prepares the %s branch for the next patch release %s.

Merge after release of %s.
`, cfg.ReleaseBranch, cfg.NextRelease, cfg.CurrentRelease)
}

// RunPatchRelease executes the patch release workflow on an existing release branch:
// 1. Opens PR-A (version + manifests for CURRENT_RELEASE)
// 2. Opens PR-B (docs asciidoc for CURRENT_RELEASE)
// 3. Opens PR-D (next patch prep)
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

	if cfg.ReleaseBranch == "" {
		cfg.ReleaseBranch = inferReleaseBranch(cfg.CurrentRelease)
	}

	prA, err := prepPatchVersion(repo, cfg)
	if err != nil {
		return err
	}
	prB, err := prepPatchDocs(repo, cfg)
	if err != nil {
		return err
	}
	prD, err := prepNextPatchOnReleaseBranch(repo, cfg)
	if err != nil {
		return err
	}

	branchesToFinalize := []workflowPR{prA, prB, prD}

	if cfg.DryRun {
		fmt.Println("\nDRY RUN: Skipping push and PR creation")
		for _, item := range branchesToFinalize {
			fmt.Printf("Branch prepared: %s\n", item.branch)
		}
		return nil
	}

	gh := NewGitHubClient(cfg.GitHubToken)
	var prs []*github.PullRequest
	for i, item := range branchesToFinalize {
		pr, err := finalizePR(repo, gh, item.branch, item.base, item.opts)
		if err != nil {
			return fmt.Errorf("failed to finalize PR %d/%d: %w", i+1, len(branchesToFinalize), err)
		}
		if pr != nil {
			prs = append(prs, pr)
		}
	}

	fmt.Printf("\n=== Patch Release Workflow Complete ===\n")
	for i, pr := range prs {
		fmt.Printf("PR %d: %s\n", i+1, pr.GetHTMLURL())
	}
	if len(prs) == 0 {
		fmt.Println("No PRs created (release already up to date)")
	}

	return nil
}

func prepPatchVersion(repo *GitRepo, cfg *ReleaseConfig) (workflowPR, error) {
	branch := fmt.Sprintf("update-version-%s", cfg.CurrentRelease)
	fmt.Printf("\n--- Preparing PR-A: version %s on %s ---\n", cfg.CurrentRelease, cfg.ReleaseBranch)

	if err := repo.EnsureBranchFrom(cfg.ReleaseBranch, branch); err != nil {
		return workflowPR{}, err
	}
	if err := UpdateVersion(cfg.CurrentRelease); err != nil {
		return workflowPR{}, err
	}
	if err := UpdateDocs(cfg.CurrentRelease); err != nil {
		return workflowPR{}, err
	}
	commitMsg := fmt.Sprintf("update version to %s", cfg.CurrentRelease)
	if _, err := repo.CommitAll(commitMsg, cfg.GitAuthorName, cfg.GitAuthorEmail); err != nil {
		return workflowPR{}, err
	}

	return workflowPR{
		branch: branch,
		base:   cfg.ReleaseBranch,
		opts: PROptions{
			Owner:     cfg.ProjectOwner,
			Repo:      cfg.ProjectRepo,
			Title:     fmt.Sprintf("[Release] Update version to %s", cfg.CurrentRelease),
			Head:      branch,
			Base:      cfg.ReleaseBranch,
			Body:      patchVersionPRBody(cfg.CurrentRelease),
			Reviewers: cfg.ProjectReviewers,
			Labels:    patchVersionPRLabels(),
		},
	}, nil
}

func prepPatchDocs(repo *GitRepo, cfg *ReleaseConfig) (workflowPR, error) {
	branch := fmt.Sprintf("update-docs-version-%s", cfg.CurrentRelease)
	fmt.Printf("\n--- Preparing PR-B: docs %s on %s ---\n", cfg.CurrentRelease, cfg.ReleaseBranch)

	if err := repo.EnsureBranchFrom(cfg.ReleaseBranch, branch); err != nil {
		return workflowPR{}, err
	}
	if err := UpdatePatchDocs(cfg.CurrentRelease); err != nil {
		return workflowPR{}, err
	}
	commitMsg := fmt.Sprintf("update docs version %s", cfg.CurrentRelease)
	if _, err := repo.CommitAll(commitMsg, cfg.GitAuthorName, cfg.GitAuthorEmail); err != nil {
		return workflowPR{}, err
	}

	return workflowPR{
		branch: branch,
		base:   cfg.ReleaseBranch,
		opts: PROptions{
			Owner:     cfg.ProjectOwner,
			Repo:      cfg.ProjectRepo,
			Title:     fmt.Sprintf("docs: update docs versions %s", cfg.CurrentRelease),
			Head:      branch,
			Base:      cfg.ReleaseBranch,
			Body:      patchDocsPRBody(cfg.CurrentRelease),
			Reviewers: cfg.ProjectReviewers,
			Labels:    patchDocsPRLabelsWithMerge(),
		},
	}, nil
}

func patchDocsPRBody(version string) string {
	return fmt.Sprintf(`Updates docs versions to %s.

Merge before the final Release build.
`, version)
}

func patchVersionPRBody(currentRelease string) string {
	return fmt.Sprintf(`Updates version to %s.

Merge before the final Release build.
`, currentRelease)
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

// CreateReleasePR creates a pull request for the release branch (legacy single-PR helper).
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
		Labels:    []string{"backport-skip", "skip-changelog"},
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

// finalizePR pushes a branch when it has new commits and creates or reuses an open PR.
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
