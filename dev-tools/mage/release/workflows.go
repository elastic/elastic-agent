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

func patchBeforeBuildPRLabels() []string {
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

type workflowPRResult struct {
	item workflowPR
	pr   *github.PullRequest
}

// RunMajorMinorRelease executes the feature-freeze workflow:
// 1. Creates the release branch from BASE_BRANCH
// 2. Opens PR-A on main (backport rule + next minor version only)
// 3. Opens PR-B on release branch (ff-release)
// 4. Opens PR-C on main (docs + deployment manifests for next minor)
// 5. Opens PR-D on release branch (next patch prep)
func RunMajorMinorRelease(cfg *ReleaseConfig) error {
	fmt.Println("=== Starting Major/Minor Release Workflow ===")

	if err := cfg.EnsureLatestRelease(); err != nil {
		return err
	}

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

	if err := ensureMajorMinorCurrentReleaseMatchesBase(repo, cfg); err != nil {
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
		warnEnsureReleaseIssueTracker(cfg, nil)
		return nil
	}

	if err := repo.CheckoutBranch(releaseBranch); err != nil {
		return err
	}
	if err := repo.Push("origin"); err != nil {
		return err
	}

	gh := NewGitHubClient(cfg.GitHubToken)
	results, err := finalizeWorkflowPRs(repo, gh, branchesToFinalize)
	if err != nil {
		return err
	}

	fmt.Printf("\n=== Major/Minor Release Workflow Complete ===\n")
	fmt.Printf("Release branch created: %s\n", releaseBranch)
	printWorkflowPRResults(results)
	fmt.Println("\nNote: Release notes PR should be created separately via .github/workflows/release-notes.yml")

	warnEnsureReleaseIssueTracker(cfg, prsFromWorkflowResults(results))
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
	// Docs and deployment manifests belong in PR-C (prepMainDocs), matching Beats.
	commitMsg := fmt.Sprintf("[Release %s] Prepare main for %s and mergify backport-%s", cfg.CurrentRelease, cfg.NextProjectMinorVersion, cfg.ReleaseBranch)
	if _, err := repo.CommitAll(commitMsg, cfg.GitAuthorName, cfg.GitAuthorEmail); err != nil {
		return workflowPR{}, err
	}

	return workflowPR{
		branch: branch,
		base:   cfg.BaseBranch,
		opts: PROptions{
			Owner:     cfg.ProjectOwner,
			Repo:      cfg.ProjectRepo,
			Title:     fmt.Sprintf("[Release %s] Prepare main for %s and mergify backport-%s", cfg.CurrentRelease, cfg.NextProjectMinorVersion, cfg.ReleaseBranch),
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
		DocBranch:      "main",
	}); err != nil {
		return workflowPR{}, err
	}
	if err := runMageUpdate(); err != nil {
		return workflowPR{}, err
	}
	commitMsg := fmt.Sprintf("[Release %s] ff-release: update versions %s", cfg.CurrentRelease, cfg.CurrentRelease)
	if _, err := repo.CommitAll(commitMsg, cfg.GitAuthorName, cfg.GitAuthorEmail); err != nil {
		return workflowPR{}, err
	}

	return workflowPR{
		branch: branch,
		base:   cfg.ReleaseBranch,
		opts: PROptions{
			Owner:     cfg.ProjectOwner,
			Repo:      cfg.ProjectRepo,
			Title:     fmt.Sprintf("[Release %s] ff-release: update versions %s", cfg.CurrentRelease, cfg.CurrentRelease),
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
	commitMsg := fmt.Sprintf("[Release %s] Update docs for %s", cfg.CurrentRelease, cfg.NextProjectMinorVersion)
	if _, err := repo.CommitAll(commitMsg, cfg.GitAuthorName, cfg.GitAuthorEmail); err != nil {
		return workflowPR{}, err
	}

	return workflowPR{
		branch: branch,
		base:   cfg.BaseBranch,
		opts: PROptions{
			Owner:     cfg.ProjectOwner,
			Repo:      cfg.ProjectRepo,
			Title:     fmt.Sprintf("[Release %s] Update docs for the %s release", cfg.CurrentRelease, cfg.NextProjectMinorVersion),
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
	if err := UpdateVersion(cfg.NextRelease); err != nil {
		return workflowPR{}, err
	}
	// Helm/K8s sync formerly applied via make check-ci after prepare-next-release.
	if err := UpdateDeploymentManifests(cfg.NextRelease); err != nil {
		return workflowPR{}, err
	}
	if err := runMageUpdate(); err != nil {
		return workflowPR{}, err
	}
	commitMsg := fmt.Sprintf("[Release %s] Update version to %s", cfg.CurrentRelease, cfg.NextRelease)
	if _, err := repo.CommitAll(commitMsg, cfg.GitAuthorName, cfg.GitAuthorEmail); err != nil {
		return workflowPR{}, err
	}

	return workflowPR{
		branch: branch,
		base:   cfg.ReleaseBranch,
		opts: PROptions{
			Owner:     cfg.ProjectOwner,
			Repo:      cfg.ProjectRepo,
			Title:     fmt.Sprintf("[Release %s] Update version to %s", cfg.CurrentRelease, cfg.NextRelease),
			Head:      branch,
			Base:      cfg.ReleaseBranch,
			Body:      prDNextPatchBody(cfg),
			Reviewers: cfg.ProjectReviewers,
			Labels:    prDNextPatchLabels(),
		},
	}, nil
}

func prAMainBody(cfg *ReleaseConfig) string {
	return fmt.Sprintf(`## [Release %s]

Prepares %s for the %s feature freeze.

- Adds Mergify backport rule for branch %s (label %s)
- Bumps version/version.go to %s (next minor)

**Merge:** before release branch work is finalized.
`, cfg.CurrentRelease, cfg.BaseBranch, cfg.CurrentRelease, cfg.ReleaseBranch, backportLabel(cfg.ReleaseBranch), cfg.NextProjectMinorVersion)
}

func prBReleaseBody(cfg *ReleaseConfig) string {
	return fmt.Sprintf(`## [Release %s]

Feature-freeze release branch updates for %s (version, docs, mage update).

**Merge:** as soon as the %s branch exists.
`, cfg.CurrentRelease, cfg.CurrentRelease, cfg.ReleaseBranch)
}

func prCMainBody(cfg *ReleaseConfig) string {
	return fmt.Sprintf(`## [Release %s]

Updates documentation and deployment manifests on %s for the next minor %s.

**Merge:** after the %s branch is created. CI may stay red until Docker images exist.
`, cfg.CurrentRelease, cfg.BaseBranch, cfg.NextProjectMinorVersion, cfg.ReleaseBranch)
}

func prDNextPatchBody(cfg *ReleaseConfig) string {
	return fmt.Sprintf(`## [Release %s]

Prepares the %s branch after release of %s.

- Bumps version/version.go to %s
- Syncs Helm/K8s deployment manifests to %s (former check-ci helm:updateAgentVersion path)
- Runs mage update for generated artifacts

**Merge:** after the release of %s.
`, cfg.CurrentRelease, cfg.ReleaseBranch, cfg.CurrentRelease, cfg.NextRelease, cfg.NextRelease, cfg.CurrentRelease)
}

func ensureMajorMinorCurrentReleaseMatchesBase(repo *GitRepo, cfg *ReleaseConfig) error {
	base := cfg.BaseBranch
	if base == "" {
		base = "main"
	}
	if err := repo.CheckoutBranch(base); err != nil {
		return err
	}
	branchVersion, err := ReadAgentVersion()
	if err != nil {
		return err
	}
	if branchVersion != cfg.CurrentRelease {
		return fmt.Errorf(
			"CURRENT_RELEASE=%s does not match version on %s (%s in version/version.go); "+
				"set CURRENT_RELEASE to the version already on %s (the minor being feature-frozen)",
			cfg.CurrentRelease, base, branchVersion, base,
		)
	}
	fmt.Printf("Verified CURRENT_RELEASE=%s matches %s on branch %s\n", cfg.CurrentRelease, branchVersion, base)
	return nil
}

// RunPatchRelease executes the patch release workflow on an existing release branch:
// 1. Opens PR-A (docs only for CURRENT_RELEASE — before build; version already on branch)
// 2. Opens PR-B (next patch version — after release)
func RunPatchRelease(cfg *ReleaseConfig) error {
	fmt.Println("=== Starting Patch Release Workflow ===")

	if err := cfg.EnsureLatestRelease(); err != nil {
		return err
	}

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

	if err := ensurePatchCurrentReleaseMatchesBranch(repo, cfg); err != nil {
		return err
	}

	prA, err := prepPatchBeforeBuild(repo, cfg)
	if err != nil {
		return err
	}
	prB, err := prepNextPatchOnReleaseBranch(repo, cfg)
	if err != nil {
		return err
	}

	branchesToFinalize := []workflowPR{prA, prB}

	if cfg.DryRun {
		fmt.Println("\nDRY RUN: Skipping push and PR creation")
		for _, item := range branchesToFinalize {
			fmt.Printf("Branch prepared: %s\n", item.branch)
		}
		warnEnsureReleaseIssueTracker(cfg, nil)
		return nil
	}

	gh := NewGitHubClient(cfg.GitHubToken)
	results, err := finalizeWorkflowPRs(repo, gh, branchesToFinalize)
	if err != nil {
		return err
	}

	fmt.Printf("\n=== Patch Release Workflow Complete ===\n")
	printWorkflowPRResults(results)
	fmt.Println("\nNote: Release notes PR should be created separately via .github/workflows/release-notes.yml")

	warnEnsureReleaseIssueTracker(cfg, prsFromWorkflowResults(results))
	return nil
}

func ensurePatchCurrentReleaseMatchesBranch(repo *GitRepo, cfg *ReleaseConfig) error {
	if err := repo.CheckoutBranch(cfg.ReleaseBranch); err != nil {
		return err
	}
	branchVersion, err := ReadAgentVersion()
	if err != nil {
		return err
	}
	if branchVersion != cfg.CurrentRelease {
		return fmt.Errorf(
			"CURRENT_RELEASE=%s does not match version on branch %s (%s in version/version.go); "+
				"set CURRENT_RELEASE to the version already on the release branch (the patch being released)",
			cfg.CurrentRelease, cfg.ReleaseBranch, branchVersion,
		)
	}
	fmt.Printf("Verified CURRENT_RELEASE=%s matches %s on branch %s\n", cfg.CurrentRelease, branchVersion, cfg.ReleaseBranch)
	return nil
}

func prepPatchBeforeBuild(repo *GitRepo, cfg *ReleaseConfig) (workflowPR, error) {
	branch := fmt.Sprintf("patch-release-%s", cfg.CurrentRelease)
	fmt.Printf("\n--- Preparing PR-A: docs for %s on %s ---\n", cfg.CurrentRelease, cfg.ReleaseBranch)

	if err := repo.EnsureBranchFrom(cfg.ReleaseBranch, branch); err != nil {
		return workflowPR{}, err
	}
	if err := UpdateDocs(cfg.CurrentRelease); err != nil {
		return workflowPR{}, err
	}
	if err := UpdatePatchDocs(cfg.CurrentRelease); err != nil {
		return workflowPR{}, err
	}
	commitMsg := fmt.Sprintf("[Release %s] Update docs versions %s", cfg.CurrentRelease, cfg.CurrentRelease)
	if _, err := repo.CommitAll(commitMsg, cfg.GitAuthorName, cfg.GitAuthorEmail); err != nil {
		return workflowPR{}, err
	}

	return workflowPR{
		branch: branch,
		base:   cfg.ReleaseBranch,
		opts: PROptions{
			Owner:     cfg.ProjectOwner,
			Repo:      cfg.ProjectRepo,
			Title:     fmt.Sprintf("[Release %s] Update docs versions %s", cfg.CurrentRelease, cfg.CurrentRelease),
			Head:      branch,
			Base:      cfg.ReleaseBranch,
			Body:      patchBeforeBuildPRBody(cfg.CurrentRelease),
			Reviewers: cfg.ProjectReviewers,
			Labels:    patchBeforeBuildPRLabels(),
		},
	}, nil
}

func patchBeforeBuildPRBody(currentRelease string) string {
	return fmt.Sprintf(`## [Release %s]

Updates docs versions to %s (former prepare-patch-release docs PR).

- Updates :stack-version: / :doc-branch: and K8s manifests
- Does **not** bump version/version.go (already %s on the release branch)

**Merge:** before the final Release build.
`, currentRelease, currentRelease, currentRelease)
}

func finalizeWorkflowPRs(repo *GitRepo, gh *GitHubClient, items []workflowPR) ([]workflowPRResult, error) {
	results := make([]workflowPRResult, 0, len(items))
	for i, item := range items {
		pr, err := finalizePR(repo, gh, item.branch, item.base, item.opts)
		if err != nil {
			return results, fmt.Errorf("failed to finalize PR %d/%d: %w", i+1, len(items), err)
		}
		results = append(results, workflowPRResult{item: item, pr: pr})
	}
	return results, nil
}

func printWorkflowPRResults(results []workflowPRResult) {
	for i, result := range results {
		fmt.Println(formatWorkflowPRLine(i+1, result))
	}
}

func prsFromWorkflowResults(results []workflowPRResult) []*github.PullRequest {
	var prs []*github.PullRequest
	for _, result := range results {
		if result.pr != nil {
			prs = append(prs, result.pr)
		}
	}
	return prs
}

func formatWorkflowPRLine(index int, result workflowPRResult) string {
	if result.pr != nil {
		return fmt.Sprintf("PR %d: %s (%s)", index, result.pr.GetHTMLURL(), prDisplayState(result.pr))
	}
	return fmt.Sprintf(
		"PR %d: skipped (no related open/merged PR for %s → %s)",
		index, result.item.branch, result.item.base,
	)
}

// finalizePR pushes a branch when it has new commits and creates or reuses an open PR.
// When the branch has nothing new to push, it still resolves a related open or merged PR
// so workflow summaries always list every expected slot.
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
		related, found, err := gh.FindRelatedPR(opts.Owner, opts.Repo, opts.Head, opts.Base, opts.Title)
		if err != nil {
			return nil, err
		}
		if found {
			fmt.Printf("Related PR #%d (%s): %s\n", related.GetNumber(), prDisplayState(related), related.GetHTMLURL())
			return related, nil
		}
		return nil, nil
	}

	if err := repo.Push("origin"); err != nil {
		return nil, err
	}

	return gh.CreatePR(opts)
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

	commitMsg := fmt.Sprintf("[Release %s] Prepare release %s", cfg.CurrentRelease, cfg.CurrentRelease)
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
