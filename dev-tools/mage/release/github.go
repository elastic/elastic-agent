// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package release

import (
	"context"
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

// CreatePR creates a new pull request
func (gh *GitHubClient) CreatePR(opts PROptions) (*github.PullRequest, error) {
	newPR := &github.NewPullRequest{
		Title:               github.String(opts.Title),
		Head:                github.String(opts.Head),
		Base:                github.String(opts.Base),
		Body:                github.String(opts.Body),
		MaintainerCanModify: github.Bool(opts.Maintainers),
		Draft:               github.Bool(opts.Draft),
	}

	pr, _, err := gh.client.PullRequests.Create(gh.ctx, opts.Owner, opts.Repo, newPR)
	if err != nil {
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
		if ghErr, ok := err.(*github.ErrorResponse); ok && ghErr.Response.StatusCode == 404 {
			return false, nil
		}
		return false, fmt.Errorf("failed to check branch: %w", err)
	}
	return true, nil
}
