// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package release

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/plumbing/storer"
	"github.com/go-git/go-git/v5/plumbing/transport/http"
)

// GitRepo wraps go-git Repository with helper methods.
type GitRepo struct {
	repo *git.Repository
	path string
}

// OpenRepo opens a git repository at the specified path.
func OpenRepo(path string) (*GitRepo, error) {
	repo, err := git.PlainOpen(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open repository: %w", err)
	}

	return &GitRepo{
		repo: repo,
		path: path,
	}, nil
}

// BranchExists reports whether a local branch exists.
func (g *GitRepo) BranchExists(branchName string) (bool, error) {
	_, err := g.repo.Reference(plumbing.NewBranchReferenceName(branchName), true)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, plumbing.ErrReferenceNotFound) {
		return false, nil
	}
	return false, fmt.Errorf("failed to check branch %s: %w", branchName, err)
}

// CreateBranch creates a new branch from the current HEAD.
func (g *GitRepo) CreateBranch(branchName string) error {
	exists, err := g.BranchExists(branchName)
	if err != nil {
		return err
	}
	if exists {
		fmt.Printf("Branch already exists: %s\n", branchName)
		return nil
	}

	headRef, err := g.repo.Head()
	if err != nil {
		return fmt.Errorf("failed to get HEAD: %w", err)
	}

	refName := plumbing.NewBranchReferenceName(branchName)
	ref := plumbing.NewHashReference(refName, headRef.Hash())

	err = g.repo.Storer.SetReference(ref)
	if err != nil {
		return fmt.Errorf("failed to create branch %s: %w", branchName, err)
	}

	fmt.Printf("Created branch: %s\n", branchName)
	return nil
}

// EnsureBranchFrom checks out baseBranch and creates or checks out branchName from that point.
func (g *GitRepo) EnsureBranchFrom(baseBranch, branchName string) error {
	if err := g.CheckoutBranch(baseBranch); err != nil {
		return fmt.Errorf("failed to checkout base branch %s: %w", baseBranch, err)
	}

	exists, err := g.BranchExists(branchName)
	if err != nil {
		return err
	}
	if exists {
		return g.CheckoutBranch(branchName)
	}

	if err := g.CreateBranch(branchName); err != nil {
		return err
	}
	return g.CheckoutBranch(branchName)
}

// EnsureBranch checks out an existing local or remote branch, or creates it from HEAD.
func (g *GitRepo) EnsureBranch(branchName string) error {
	exists, err := g.BranchExists(branchName)
	if err != nil {
		return err
	}
	if exists {
		return g.CheckoutBranch(branchName)
	}

	remoteRef, err := g.repo.Reference(plumbing.NewRemoteReferenceName("origin", branchName), true)
	if err == nil {
		localRef := plumbing.NewHashReference(plumbing.NewBranchReferenceName(branchName), remoteRef.Hash())
		if err := g.repo.Storer.SetReference(localRef); err != nil {
			return fmt.Errorf("failed to create local branch %s from origin: %w", branchName, err)
		}
		fmt.Printf("Created local branch from origin: %s\n", branchName)
		return g.CheckoutBranch(branchName)
	}
	if !errors.Is(err, plumbing.ErrReferenceNotFound) {
		return fmt.Errorf("failed to check remote branch %s: %w", branchName, err)
	}

	if err := g.CreateBranch(branchName); err != nil {
		return err
	}
	return g.CheckoutBranch(branchName)
}

// SyncSubmodules aligns submodule working trees with the commits recorded at HEAD.
func (g *GitRepo) SyncSubmodules() error {
	cmd := exec.CommandContext(context.Background(), "git", "submodule", "update", "--init", "--recursive", "--force")
	cmd.Dir = g.path
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to sync submodules: %w: %s", err, string(output))
	}
	return nil
}

// CheckoutBranch checks out an existing branch.
func (g *GitRepo) CheckoutBranch(branchName string) error {
	currentBranch, err := g.GetCurrentBranch()
	if err == nil && currentBranch == branchName {
		fmt.Printf("Already on branch: %s\n", branchName)
		return g.SyncSubmodules()
	}

	if err := g.SyncSubmodules(); err != nil {
		return err
	}

	w, err := g.repo.Worktree()
	if err != nil {
		return fmt.Errorf("failed to get worktree: %w", err)
	}

	err = w.Checkout(&git.CheckoutOptions{
		Branch: plumbing.NewBranchReferenceName(branchName),
	})
	if err != nil {
		return fmt.Errorf("failed to checkout branch %s: %w", branchName, err)
	}

	if err := g.SyncSubmodules(); err != nil {
		return fmt.Errorf("failed to sync submodules after checking out %s: %w", branchName, err)
	}

	fmt.Printf("Checked out branch: %s\n", branchName)
	return nil
}

// CommitAll stages all changes and creates a commit.
func (g *GitRepo) CommitAll(message, authorName, authorEmail string) (bool, error) {
	w, err := g.repo.Worktree()
	if err != nil {
		return false, fmt.Errorf("failed to get worktree: %w", err)
	}

	err = w.AddGlob(".")
	if err != nil {
		return false, fmt.Errorf("failed to stage changes: %w", err)
	}

	status, err := w.Status()
	if err != nil {
		return false, fmt.Errorf("failed to get status: %w", err)
	}
	if status.IsClean() {
		fmt.Println("No changes to commit")
		return false, nil
	}

	commit, err := w.Commit(message, &git.CommitOptions{
		Author: &object.Signature{
			Name:  authorName,
			Email: authorEmail,
			When:  time.Now(),
		},
	})
	if err != nil {
		return false, fmt.Errorf("failed to commit: %w", err)
	}

	fmt.Printf("Created commit: %s\n", commit.String())
	return true, nil
}

// HasCommitsAheadOf reports whether HEAD has commits not reachable from baseBranch.
func (g *GitRepo) HasCommitsAheadOf(baseBranch string) (bool, error) {
	headRef, err := g.repo.Head()
	if err != nil {
		return false, fmt.Errorf("failed to get HEAD: %w", err)
	}

	baseRef, err := g.repo.Reference(plumbing.NewBranchReferenceName(baseBranch), true)
	if err != nil {
		if errors.Is(err, plumbing.ErrReferenceNotFound) {
			return true, nil
		}
		return false, fmt.Errorf("failed to get base branch %s: %w", baseBranch, err)
	}

	if headRef.Hash() == baseRef.Hash() {
		return false, nil
	}

	commitIter, err := g.repo.Log(&git.LogOptions{From: headRef.Hash()})
	if err != nil {
		return false, fmt.Errorf("failed to walk commits: %w", err)
	}
	defer commitIter.Close()

	foundBase := false
	err = commitIter.ForEach(func(c *object.Commit) error {
		if c.Hash == baseRef.Hash() {
			foundBase = true
			return storer.ErrStop
		}
		return nil
	})
	if err != nil && !errors.Is(err, storer.ErrStop) {
		return false, fmt.Errorf("failed to compare commits with %s: %w", baseBranch, err)
	}

	if foundBase {
		return true, nil
	}

	return headRef.Hash() != baseRef.Hash(), nil
}

// Push pushes the current branch to the remote.
func (g *GitRepo) Push(remoteName string) error {
	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		return fmt.Errorf("GITHUB_TOKEN environment variable is required for pushing")
	}

	currentBranch, err := g.GetCurrentBranch()
	if err != nil {
		return err
	}

	refSpec := config.RefSpec(fmt.Sprintf("refs/heads/%s:refs/heads/%s", currentBranch, currentBranch))

	err = g.repo.Push(&git.PushOptions{
		RemoteName: remoteName,
		RefSpecs:   []config.RefSpec{refSpec},
		Auth: &http.BasicAuth{
			Username: "git",
			Password: token,
		},
	})
	if err != nil && !errors.Is(err, git.NoErrAlreadyUpToDate) {
		return fmt.Errorf("failed to push: %w", err)
	}

	fmt.Printf("Pushed branch %s to remote: %s\n", currentBranch, remoteName)
	return nil
}

// GetCurrentBranch returns the name of the current branch.
func (g *GitRepo) GetCurrentBranch() (string, error) {
	headRef, err := g.repo.Head()
	if err != nil {
		return "", fmt.Errorf("failed to get HEAD: %w", err)
	}

	if !headRef.Name().IsBranch() {
		return "", fmt.Errorf("HEAD is not a branch")
	}

	return headRef.Name().Short(), nil
}

// IsClean checks if the working directory is clean.
func (g *GitRepo) IsClean() (bool, error) {
	w, err := g.repo.Worktree()
	if err != nil {
		return false, fmt.Errorf("failed to get worktree: %w", err)
	}

	status, err := w.Status()
	if err != nil {
		return false, fmt.Errorf("failed to get status: %w", err)
	}

	return status.IsClean(), nil
}

// SetRemoteURL sets the URL for a remote.
func (g *GitRepo) SetRemoteURL(remoteName, url string) error {
	_, err := g.repo.Remote(remoteName)
	if errors.Is(err, git.ErrRemoteNotFound) {
		_, err = g.repo.CreateRemote(&config.RemoteConfig{
			Name: remoteName,
			URLs: []string{url},
		})
		if err != nil {
			return fmt.Errorf("failed to create remote: %w", err)
		}
		fmt.Printf("Created remote %s: %s\n", remoteName, url)
		return nil
	} else if err != nil {
		return fmt.Errorf("failed to get remote: %w", err)
	}

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

	fmt.Printf("Updated remote %s: %s\n", remoteName, url)
	return nil
}
