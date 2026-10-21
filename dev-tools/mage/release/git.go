// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package release

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
)

const (
	submoduleSyncAttempts  = 5
	submoduleSyncRetryWait = 200 * time.Millisecond
)

// isSubmoduleIndexLockError reports whether git submodule update failed because
// another process briefly held a submodule index.lock (common under rapid
// branch switches).
func isSubmoduleIndexLockError(output string) bool {
	return strings.Contains(output, "index.lock") &&
		(strings.Contains(output, "File exists") || strings.Contains(output, "Unable to create"))
}

// GitRepo wraps go-git Repository with helper methods.
// Worktree mutations that need objects (checkout, status, commit, push, ahead
// checks) use the git CLI so Buildkite --reference / shared clones work.
// go-git does not follow objects/info/alternates and returns "object not found".
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

// runGit runs git in the repository path and returns combined stdout/stderr.
func (g *GitRepo) runGit(args ...string) (string, error) {
	cmd := exec.CommandContext(context.Background(), "git", args...)
	cmd.Dir = g.path
	output, err := cmd.CombinedOutput()
	if err != nil {
		return string(output), fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(output)))
	}
	return string(output), nil
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

	if _, err := g.runGit("branch", branchName); err != nil {
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
// Transient submodule index.lock contention is retried with backoff.
func (g *GitRepo) SyncSubmodules() error {
	var lastErr error
	var lastOutput string
	for attempt := 1; attempt <= submoduleSyncAttempts; attempt++ {
		output, err := g.runGit("submodule", "update", "--init", "--recursive", "--force")
		if err == nil {
			return nil
		}
		lastErr = err
		lastOutput = output
		if !isSubmoduleIndexLockError(lastOutput) || attempt == submoduleSyncAttempts {
			break
		}
		fmt.Printf("Submodule sync hit index.lock (attempt %d/%d); retrying...\n", attempt, submoduleSyncAttempts)
		time.Sleep(submoduleSyncRetryWait * time.Duration(attempt))
	}
	return fmt.Errorf("failed to sync submodules: %w: %s", lastErr, lastOutput)
}

// CheckoutBranch checks out an existing branch, then syncs submodules to HEAD.
func (g *GitRepo) CheckoutBranch(branchName string) error {
	currentBranch, err := g.GetCurrentBranch()
	if err == nil && currentBranch == branchName {
		fmt.Printf("Already on branch: %s\n", branchName)
		return g.SyncSubmodules()
	}

	// Force discards unstaged submodule drift left by the previous branch's
	// gitlink; SyncSubmodules immediately after restores HEAD's pins.
	if _, err := g.runGit("checkout", "-f", branchName); err != nil {
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
	if _, err := g.runGit("add", "-A"); err != nil {
		return false, fmt.Errorf("failed to stage changes: %w", err)
	}

	clean, err := g.IsClean()
	if err != nil {
		return false, err
	}
	if clean {
		fmt.Println("No changes to commit")
		return false, nil
	}

	cmd := exec.CommandContext(context.Background(), "git",
		"-c", "user.name="+authorName,
		"-c", "user.email="+authorEmail,
		"commit", "-F", "-",
	)
	cmd.Dir = g.path
	cmd.Stdin = strings.NewReader(message)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return false, fmt.Errorf("failed to commit: %w: %s", err, strings.TrimSpace(string(output)))
	}

	hash, err := g.runGit("rev-parse", "HEAD")
	if err != nil {
		return false, fmt.Errorf("failed to resolve new commit: %w", err)
	}
	fmt.Printf("Created commit: %s\n", strings.TrimSpace(hash))
	return true, nil
}

// HasCommitsAheadOf reports whether HEAD has commits not reachable from baseBranch.
// Equal or behind returns false; ahead or diverged returns true.
// A missing base branch is treated as ahead (true).
func (g *GitRepo) HasCommitsAheadOf(baseBranch string) (bool, error) {
	if _, err := g.runGit("rev-parse", "--verify", "--quiet", "refs/heads/"+baseBranch); err != nil {
		return true, nil
	}

	out, err := g.runGit("rev-list", "--count", baseBranch+"..HEAD")
	if err != nil {
		return false, fmt.Errorf("failed to compare commits with %s: %w", baseBranch, err)
	}
	count, err := strconv.Atoi(strings.TrimSpace(out))
	if err != nil {
		return false, fmt.Errorf("failed to parse rev-list count for %s: %w", baseBranch, err)
	}
	return count > 0, nil
}

// Push pushes the current branch to the remote using the given GitHub token.
func (g *GitRepo) Push(remoteName, token string) error {
	if token == "" {
		return fmt.Errorf("GitHub token is required for pushing")
	}

	currentBranch, err := g.GetCurrentBranch()
	if err != nil {
		return err
	}

	refSpec := fmt.Sprintf("refs/heads/%s:refs/heads/%s", currentBranch, currentBranch)
	auth := base64.StdEncoding.EncodeToString([]byte("x-access-token:" + token))
	cmd := exec.CommandContext(context.Background(), "git",
		"-c", "http.extraHeader=Authorization: Basic "+auth,
		"push", remoteName, refSpec,
	)
	cmd.Dir = g.path
	output, err := cmd.CombinedOutput()
	if err != nil {
		// Match prior go-git behavior: already up-to-date is success.
		if bytes.Contains(output, []byte("Everything up-to-date")) {
			fmt.Printf("Pushed branch %s to remote: %s\n", currentBranch, remoteName)
			return nil
		}
		return fmt.Errorf("failed to push: %w: %s", err, strings.TrimSpace(string(output)))
	}

	fmt.Printf("Pushed branch %s to remote: %s\n", currentBranch, remoteName)
	return nil
}

// GetCurrentBranch returns the name of the current branch.
func (g *GitRepo) GetCurrentBranch() (string, error) {
	out, err := g.runGit("rev-parse", "--abbrev-ref", "HEAD")
	if err != nil {
		return "", fmt.Errorf("failed to get HEAD: %w", err)
	}
	name := strings.TrimSpace(out)
	if name == "" || name == "HEAD" {
		return "", fmt.Errorf("HEAD is not a branch")
	}
	return name, nil
}

// IsClean checks if the working directory is clean.
func (g *GitRepo) IsClean() (bool, error) {
	out, err := g.runGit("status", "--porcelain")
	if err != nil {
		return false, fmt.Errorf("failed to get status: %w", err)
	}
	return strings.TrimSpace(out) == "", nil
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
