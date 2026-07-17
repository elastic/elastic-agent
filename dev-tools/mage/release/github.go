// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package release

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/google/go-github/v68/github"
)

// GitHubClient wraps the GitHub API client.
type GitHubClient struct {
	client *github.Client
	ctx    context.Context
}

// PROptions holds options for creating a pull request.
type PROptions struct {
	Owner     string
	Repo      string
	Title     string
	Head      string
	Base      string
	Body      string
	Draft     bool
	Reviewers []string
	Labels    []string
}

// NewGitHubClient creates a new GitHub API client.
func NewGitHubClient(token string) *GitHubClient {
	ctx := context.Background()
	return &GitHubClient{
		client: github.NewClient(nil).WithAuthToken(token),
		ctx:    ctx,
	}
}

// NewGitHubClientFromEnv creates a GitHub client using GITHUB_TOKEN env var.
func NewGitHubClientFromEnv() (*GitHubClient, error) {
	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		return nil, fmt.Errorf("GITHUB_TOKEN environment variable not set")
	}
	return NewGitHubClient(token), nil
}

// CreatePR creates a pull request, or returns an existing open PR with the same head and base.
func (gh *GitHubClient) CreatePR(opts PROptions) (*github.PullRequest, error) {
	existingPR, found, err := gh.FindOpenPR(opts.Owner, opts.Repo, opts.Head, opts.Base)
	if err != nil {
		return nil, err
	}
	if found {
		fmt.Printf("Open PR already exists #%d: %s\n", existingPR.GetNumber(), existingPR.GetHTMLURL())
		gh.ensurePRLabels(opts.Owner, opts.Repo, existingPR.GetNumber(), opts.Labels)
		return existingPR, nil
	}

	newPR := &github.NewPullRequest{
		Title: github.Ptr(opts.Title),
		Head:  github.Ptr(opts.Head),
		Base:  github.Ptr(opts.Base),
		Body:  github.Ptr(opts.Body),
		Draft: github.Ptr(opts.Draft),
	}

	pr, _, err := gh.client.PullRequests.Create(gh.ctx, opts.Owner, opts.Repo, newPR)
	if err != nil {
		return nil, fmt.Errorf("failed to create PR: %w", err)
	}

	if len(opts.Reviewers) > 0 {
		reviewersReq := github.ReviewersRequest{
			Reviewers: opts.Reviewers,
		}
		_, _, err = gh.client.PullRequests.RequestReviewers(gh.ctx, opts.Owner, opts.Repo, pr.GetNumber(), reviewersReq)
		if err != nil {
			fmt.Printf("Warning: failed to add reviewers: %v\n", err)
		}
	}

	gh.ensurePRLabels(opts.Owner, opts.Repo, pr.GetNumber(), opts.Labels)

	fmt.Printf("Created PR #%d: %s\n", pr.GetNumber(), pr.GetHTMLURL())
	return pr, nil
}

// FindOpenPR returns an open pull request for the given head and base branches, if one exists.
func (gh *GitHubClient) FindOpenPR(owner, repo, head, base string) (*github.PullRequest, bool, error) {
	headQuery := head
	if !strings.Contains(head, ":") {
		headQuery = fmt.Sprintf("%s:%s", owner, head)
	}

	prs, _, err := gh.client.PullRequests.List(gh.ctx, owner, repo, &github.PullRequestListOptions{
		State: "open",
		Head:  headQuery,
		Base:  base,
		ListOptions: github.ListOptions{
			PerPage: 1,
		},
	})
	if err != nil {
		return nil, false, fmt.Errorf("failed to list pull requests: %w", err)
	}
	if len(prs) == 0 {
		return nil, false, nil
	}

	return prs[0], true, nil
}

// mergeLabelDefs are auto-created when missing so merge-timing labels can be applied.
var mergeLabelDefs = map[string]struct {
	Color       string
	Description string
}{
	mergeLabelFFDay: {
		Color:       "B60205",
		Description: "Merge 1st: feature-freeze day (main)",
	},
	mergeLabelAfterBranch: {
		Color:       "D93F0B",
		Description: "Merge 2nd: ASAP after release branch exists",
	},
	mergeLabelAfterImages: {
		Color:       "FBCA04",
		Description: "Merge 3rd: after branch exists; may wait on Docker images",
	},
	mergeLabelAfterRelease: {
		Color:       "0E8A16",
		Description: "Merge 4th: after release day",
	},
	mergeLabelBeforeBuild: {
		Color:       "B60205",
		Description: "Merge before the final patch release build",
	},
}

func (gh *GitHubClient) ensurePRLabels(owner, repo string, number int, labels []string) {
	if len(labels) == 0 {
		return
	}
	for _, label := range labels {
		if def, ok := mergeLabelDefs[label]; ok {
			if err := gh.EnsureLabel(owner, repo, label, def.Color, def.Description); err != nil {
				fmt.Printf("Warning: failed to ensure label %q: %v\n", label, err)
			}
		}
	}
	if err := gh.AddLabels(owner, repo, number, labels); err != nil {
		fmt.Printf("Warning: failed to add labels: %v\n", err)
	}
}

// EnsureLabel creates a repository label if it does not already exist.
func (gh *GitHubClient) EnsureLabel(owner, repo, name, color, description string) error {
	_, resp, err := gh.client.Issues.GetLabel(gh.ctx, owner, repo, name)
	if err == nil {
		return nil
	}
	if resp == nil || resp.StatusCode != http.StatusNotFound {
		return fmt.Errorf("failed to get label %q: %w", name, err)
	}

	_, _, err = gh.client.Issues.CreateLabel(gh.ctx, owner, repo, &github.Label{
		Name:        github.Ptr(name),
		Color:       github.Ptr(color),
		Description: github.Ptr(description),
	})
	if err != nil {
		return fmt.Errorf("failed to create label %q: %w", name, err)
	}
	fmt.Printf("Created label %q\n", name)
	return nil
}

// AddLabels adds labels to a pull request or issue.
func (gh *GitHubClient) AddLabels(owner, repo string, number int, labels []string) error {
	_, _, err := gh.client.Issues.AddLabelsToIssue(gh.ctx, owner, repo, number, labels)
	if err != nil {
		return fmt.Errorf("failed to add labels: %w", err)
	}

	fmt.Printf("Added labels to #%d: %v\n", number, labels)
	return nil
}

// GetDefaultBranch gets the default branch for a repository.
func (gh *GitHubClient) GetDefaultBranch(owner, repo string) (string, error) {
	repository, _, err := gh.client.Repositories.Get(gh.ctx, owner, repo)
	if err != nil {
		return "", fmt.Errorf("failed to get repository: %w", err)
	}

	return repository.GetDefaultBranch(), nil
}

// BranchExists checks if a branch exists in the remote repository.
func (gh *GitHubClient) BranchExists(owner, repo, branch string) (bool, error) {
	_, _, err := gh.client.Repositories.GetBranch(gh.ctx, owner, repo, branch, 0)
	if err != nil {
		var ghErr *github.ErrorResponse
		if errors.As(err, &ghErr) && ghErr.Response != nil && ghErr.Response.StatusCode == 404 {
			return false, nil
		}
		return false, fmt.Errorf("failed to check branch: %w", err)
	}
	return true, nil
}

// releasesLookupOwner and releasesLookupRepo are the canonical repo for published releases.
// Forks typically lack release history, so workflows always resolve LatestRelease from here.
const (
	releasesLookupOwner = "elastic"
	releasesLookupRepo  = "elastic-agent"
)

// LatestReleaseBefore returns the highest published release version with the same major
// that is strictly less than currentVersion (e.g. current 9.5.0 → 9.4.3).
func (gh *GitHubClient) LatestReleaseBefore(owner, repo, currentVersion string) (string, error) {
	versions, err := gh.listReleaseVersions(owner, repo)
	if err != nil {
		return "", err
	}
	return selectLatestReleaseBefore(versions, currentVersion)
}

func (gh *GitHubClient) listReleaseVersions(owner, repo string) ([]string, error) {
	var versions []string
	opts := &github.ListOptions{PerPage: 100}
	for {
		releases, resp, err := gh.client.Repositories.ListReleases(gh.ctx, owner, repo, opts)
		if err != nil {
			return nil, fmt.Errorf("failed to list releases for %s/%s: %w", owner, repo, err)
		}
		for _, rel := range releases {
			tag := rel.GetTagName()
			if tag == "" {
				continue
			}
			versions = append(versions, tag)
		}
		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}
	return versions, nil
}
