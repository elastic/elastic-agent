// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package release

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/google/go-github/v68/github"
)

// GitHubClient wraps the GitHub API client
type GitHubClient struct {
	client *github.Client
	ctx    context.Context
}

// NewGitHubClient creates a new GitHub client with authentication
func NewGitHubClient(token string) *GitHubClient {
	ctx := context.Background()
	client := github.NewClient(nil).WithAuthToken(token)

	return &GitHubClient{
		client: client,
		ctx:    ctx,
	}
}

// NewGitHubClientFromEnv creates a GitHub client using GITHUB_TOKEN env var
func NewGitHubClientFromEnv() (*GitHubClient, error) {
	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		return nil, fmt.Errorf("GITHUB_TOKEN environment variable not set")
	}
	return NewGitHubClient(token), nil
}

// PROptions contains options for creating a pull request
type PROptions struct {
	Owner       string
	Repo        string
	Title       string
	Head        string // branch name
	Base        string // target branch (e.g., "main")
	Body        string
	Draft       bool
	Maintainers bool // allow maintainers to edit
}

// FindOpenPR returns an open pull request matching head and base, or nil if none exists.
func (gh *GitHubClient) FindOpenPR(owner, repo, head, base string) (*github.PullRequest, error) {
	headRef := fmt.Sprintf("%s:%s", owner, head)
	prs, _, err := gh.client.PullRequests.List(gh.ctx, owner, repo, &github.PullRequestListOptions{
		State: "open",
		Head:  headRef,
		Base:  base,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list pull requests: %w", err)
	}

	if len(prs) == 0 {
		return nil, nil
	}

	return prs[0], nil
}

// CreatePR creates a new pull request.
// If an open pull request already exists for the same head and base, it is returned instead (idempotent).
func (gh *GitHubClient) CreatePR(opts PROptions) (*github.PullRequest, error) {
	existing, err := gh.FindOpenPR(opts.Owner, opts.Repo, opts.Head, opts.Base)
	if err != nil {
		return nil, err
	}
	if existing != nil {
		fmt.Printf("  Open PR #%d already exists: %s\n", existing.GetNumber(), existing.GetHTMLURL())
		return existing, nil
	}

	newPR := &github.NewPullRequest{
		Title:               github.Ptr(opts.Title),
		Head:                github.Ptr(opts.Head),
		Base:                github.Ptr(opts.Base),
		Body:                github.Ptr(opts.Body),
		MaintainerCanModify: github.Ptr(opts.Maintainers),
		Draft:               github.Ptr(opts.Draft),
	}

	pr, _, err := gh.client.PullRequests.Create(gh.ctx, opts.Owner, opts.Repo, newPR)
	if err != nil {
		var ghErr *github.ErrorResponse
		if errors.As(err, &ghErr) && ghErr.Response != nil && ghErr.Response.StatusCode == 422 {
			existing, findErr := gh.FindOpenPR(opts.Owner, opts.Repo, opts.Head, opts.Base)
			if findErr == nil && existing != nil {
				fmt.Printf("  Open PR #%d already exists: %s\n", existing.GetNumber(), existing.GetHTMLURL())
				return existing, nil
			}
		}
		return nil, fmt.Errorf("failed to create PR: %w", err)
	}

	fmt.Printf("✓ Created PR #%d: %s\n", pr.GetNumber(), pr.GetHTMLURL())
	return pr, nil
}

// AddLabels adds labels to a pull request
func (gh *GitHubClient) AddLabels(owner, repo string, prNumber int, labels []string) error {
	_, _, err := gh.client.Issues.AddLabelsToIssue(gh.ctx, owner, repo, prNumber, labels)
	if err != nil {
		return fmt.Errorf("failed to add labels: %w", err)
	}

	fmt.Printf("✓ Added labels to PR #%d: %v\n", prNumber, labels)
	return nil
}

// RequestReviewers requests reviews from users
func (gh *GitHubClient) RequestReviewers(owner, repo string, prNumber int, reviewers []string) error {
	reviewReq := github.ReviewersRequest{
		Reviewers: reviewers,
	}

	_, _, err := gh.client.PullRequests.RequestReviewers(gh.ctx, owner, repo, prNumber, reviewReq)
	if err != nil {
		return fmt.Errorf("failed to request reviewers: %w", err)
	}

	fmt.Printf("✓ Requested reviews from: %v\n", reviewers)
	return nil
}

// GetDefaultBranch gets the default branch for a repository
func (gh *GitHubClient) GetDefaultBranch(owner, repo string) (string, error) {
	repository, _, err := gh.client.Repositories.Get(gh.ctx, owner, repo)
	if err != nil {
		return "", fmt.Errorf("failed to get repository: %w", err)
	}

	return repository.GetDefaultBranch(), nil
}

// BranchExists checks if a branch exists in the repository
func (gh *GitHubClient) BranchExists(owner, repo, branch string) (bool, error) {
	_, _, err := gh.client.Repositories.GetBranch(gh.ctx, owner, repo, branch, 0)
	if err != nil {
		var ghErr *github.ErrorResponse
		if errors.As(err, &ghErr) && ghErr.Response.StatusCode == 404 {
			return false, nil
		}
		return false, fmt.Errorf("failed to check branch: %w", err)
	}
	return true, nil
}
