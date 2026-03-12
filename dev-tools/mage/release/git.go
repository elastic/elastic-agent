// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package release

import (
	"fmt"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
)

// GitRepo represents a Git repository with common operations
type GitRepo struct {
	repo *git.Repository
}

// OpenRepo opens the Git repository at the given path
func OpenRepo(path string) (*GitRepo, error) {
	repo, err := git.PlainOpen(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open git repo: %w", err)
	}
	return &GitRepo{repo: repo}, nil
}

// CreateBranch creates and checks out a new branch
func (g *GitRepo) CreateBranch(branchName string) error {
	w, err := g.repo.Worktree()
	if err != nil {
		return fmt.Errorf("failed to get worktree: %w", err)
	}

	// Get current HEAD reference
	headRef, err := g.repo.Head()
	if err != nil {
		return fmt.Errorf("failed to get HEAD: %w", err)
	}

	// Create new branch reference
	refName := plumbing.NewBranchReferenceName(branchName)
	ref := plumbing.NewHashReference(refName, headRef.Hash())

	err = g.repo.Storer.SetReference(ref)
	if err != nil {
		return fmt.Errorf("failed to create branch: %w", err)
	}

	// Checkout the new branch
	err = w.Checkout(&git.CheckoutOptions{
		Branch: refName,
	})
	if err != nil {
		return fmt.Errorf("failed to checkout branch: %w", err)
	}

	fmt.Printf("✓ Created and checked out branch: %s\n", branchName)
	return nil
}

// CommitAll commits all changes with the given message
func (g *GitRepo) CommitAll(message, authorName, authorEmail string) error {
	w, err := g.repo.Worktree()
	if err != nil {
		return fmt.Errorf("failed to get worktree: %w", err)
	}

	// Add all changes
	err = w.AddWithOptions(&git.AddOptions{
		All: true,
	})
	if err != nil {
		return fmt.Errorf("failed to add changes: %w", err)
	}

	// Create commit
	commit, err := w.Commit(message, &git.CommitOptions{
		Author: &object.Signature{
			Name:  authorName,
			Email: authorEmail,
			When:  time.Now(),
		},
	})
	if err != nil {
		return fmt.Errorf("failed to commit: %w", err)
	}

	fmt.Printf("✓ Committed changes: %s\n", commit.String()[:7])
	return nil
}

// Push pushes the current branch to the remote
func (g *GitRepo) Push(remoteName string) error {
	err := g.repo.Push(&git.PushOptions{
		RemoteName: remoteName,
	})
	if err != nil && err != git.NoErrAlreadyUpToDate {
		return fmt.Errorf("failed to push: %w", err)
	}

	if err == git.NoErrAlreadyUpToDate {
		fmt.Println("  Branch already up to date on remote")
	} else {
		fmt.Printf("✓ Pushed to remote: %s\n", remoteName)
	}
	return nil
}

// GetCurrentBranch returns the name of the current branch
func (g *GitRepo) GetCurrentBranch() (string, error) {
	ref, err := g.repo.Head()
	if err != nil {
		return "", fmt.Errorf("failed to get HEAD: %w", err)
	}

	if !ref.Name().IsBranch() {
		return "", fmt.Errorf("HEAD is not a branch")
	}

	return ref.Name().Short(), nil
}

// SetRemoteURL sets the URL for a remote
func (g *GitRepo) SetRemoteURL(remoteName, url string) error {
	_, err := g.repo.Remote(remoteName)
	if err == git.ErrRemoteNotFound {
		// Remote doesn't exist, create it
		_, err = g.repo.CreateRemote(&config.RemoteConfig{
			Name: remoteName,
			URLs: []string{url},
		})
		if err != nil {
			return fmt.Errorf("failed to create remote: %w", err)
		}
		fmt.Printf("✓ Created remote %s: %s\n", remoteName, url)
		return nil
	} else if err != nil {
		return fmt.Errorf("failed to get remote: %w", err)
	}

	// Update remote URL
	err = g.repo.DeleteRemote(remoteName)
	if err != nil {
		return fmt.Errorf("failed to delete remote: %w", err)
	}

	_, err = g.repo.CreateRemote(&config.RemoteConfig{
		Name: remoteName,
		URLs: []string{url},
	})
	if err != nil {
		return fmt.Errorf("failed to recreate remote: %w", err)
	}

	fmt.Printf("✓ Updated remote %s: %s\n", remoteName, url)
	return nil
}
