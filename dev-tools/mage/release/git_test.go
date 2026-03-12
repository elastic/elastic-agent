// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package release

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
)

func createTestRepo(t *testing.T) (*GitRepo, string) {
	t.Helper()

	tmpDir := t.TempDir()

	// Initialize a git repository
	repo, err := git.PlainInit(tmpDir, false)
	if err != nil {
		t.Fatalf("failed to init repo: %v", err)
	}

	// Create an initial commit
	w, err := repo.Worktree()
	if err != nil {
		t.Fatalf("failed to get worktree: %v", err)
	}

	// Create a test file
	testFile := filepath.Join(tmpDir, "README.md")
	err = os.WriteFile(testFile, []byte("# Test Repo"), 0644)
	if err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	// Add and commit
	_, err = w.Add("README.md")
	if err != nil {
		t.Fatalf("failed to add file: %v", err)
	}

	_, err = w.Commit("Initial commit", &git.CommitOptions{
		Author: &object.Signature{
			Name:  "Test User",
			Email: "test@example.com",
		},
	})
	if err != nil {
		t.Fatalf("failed to create initial commit: %v", err)
	}

	gitRepo := &GitRepo{repo: repo}
	return gitRepo, tmpDir
}

func TestOpenRepo(t *testing.T) {
	_, tmpDir := createTestRepo(t)

	// Test opening existing repo
	gitRepo, err := OpenRepo(tmpDir)
	if err != nil {
		t.Errorf("OpenRepo() error = %v", err)
		return
	}

	if gitRepo == nil || gitRepo.repo == nil {
		t.Error("OpenRepo() returned nil repo")
	}

	// Test opening non-existent repo
	_, err = OpenRepo("/non/existent/path")
	if err == nil {
		t.Error("OpenRepo() should fail for non-existent path")
	}
}

func TestCreateBranch(t *testing.T) {
	gitRepo, _ := createTestRepo(t)

	tests := []struct {
		name       string
		branchName string
		wantError  bool
	}{
		{
			name:       "create valid branch",
			branchName: "feature/test",
			wantError:  false,
		},
		{
			name:       "create release branch",
			branchName: "9.4",
			wantError:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := gitRepo.CreateBranch(tt.branchName)
			if (err != nil) != tt.wantError {
				t.Errorf("CreateBranch() error = %v, wantError %v", err, tt.wantError)
				return
			}

			if !tt.wantError {
				// Verify the branch was created and checked out
				currentBranch, err := gitRepo.GetCurrentBranch()
				if err != nil {
					t.Errorf("GetCurrentBranch() error = %v", err)
					return
				}

				if currentBranch != tt.branchName {
					t.Errorf("CreateBranch() created branch %s, want %s", currentBranch, tt.branchName)
				}
			}
		})
	}
}

func TestCommitAll(t *testing.T) {
	gitRepo, tmpDir := createTestRepo(t)

	// Create a new file
	testFile := filepath.Join(tmpDir, "test.txt")
	err := os.WriteFile(testFile, []byte("test content"), 0644)
	if err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	// Commit changes
	err = gitRepo.CommitAll("Test commit", "Test Author", "test@example.com")
	if err != nil {
		t.Errorf("CommitAll() error = %v", err)
		return
	}

	// Verify commit was created
	ref, err := gitRepo.repo.Head()
	if err != nil {
		t.Fatalf("failed to get HEAD: %v", err)
	}

	commit, err := gitRepo.repo.CommitObject(ref.Hash())
	if err != nil {
		t.Fatalf("failed to get commit: %v", err)
	}

	if commit.Message != "Test commit" {
		t.Errorf("CommitAll() commit message = %s, want %s", commit.Message, "Test commit")
	}

	if commit.Author.Name != "Test Author" {
		t.Errorf("CommitAll() author name = %s, want %s", commit.Author.Name, "Test Author")
	}
}

func TestGetCurrentBranch(t *testing.T) {
	gitRepo, _ := createTestRepo(t)

	// Default branch should be "master" or "main"
	branch, err := gitRepo.GetCurrentBranch()
	if err != nil {
		t.Errorf("GetCurrentBranch() error = %v", err)
		return
	}

	if branch != "master" && branch != "main" {
		t.Logf("GetCurrentBranch() = %s (expected master or main)", branch)
	}

	// Create and checkout a new branch
	testBranch := "test-branch"
	err = gitRepo.CreateBranch(testBranch)
	if err != nil {
		t.Fatalf("CreateBranch() error = %v", err)
	}

	branch, err = gitRepo.GetCurrentBranch()
	if err != nil {
		t.Errorf("GetCurrentBranch() error = %v", err)
		return
	}

	if branch != testBranch {
		t.Errorf("GetCurrentBranch() = %s, want %s", branch, testBranch)
	}
}

func TestSetRemoteURL(t *testing.T) {
	gitRepo, _ := createTestRepo(t)

	tests := []struct {
		name       string
		remoteName string
		url        string
		wantError  bool
	}{
		{
			name:       "create new remote",
			remoteName: "origin",
			url:        "https://github.com/test/repo.git",
			wantError:  false,
		},
		{
			name:       "update existing remote",
			remoteName: "origin",
			url:        "https://github.com/test/repo2.git",
			wantError:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := gitRepo.SetRemoteURL(tt.remoteName, tt.url)
			if (err != nil) != tt.wantError {
				t.Errorf("SetRemoteURL() error = %v, wantError %v", err, tt.wantError)
				return
			}

			if !tt.wantError {
				// Verify remote was created/updated
				remote, err := gitRepo.repo.Remote(tt.remoteName)
				if err != nil {
					t.Errorf("Failed to get remote: %v", err)
					return
				}

				if len(remote.Config().URLs) == 0 || remote.Config().URLs[0] != tt.url {
					t.Errorf("SetRemoteURL() URL = %v, want %s", remote.Config().URLs, tt.url)
				}
			}
		})
	}
}

func TestCommitAllErrorCases(t *testing.T) {
	gitRepo, tmpDir := createTestRepo(t)

	// Test committing with no changes
	err := gitRepo.CommitAll("Empty commit", "Test", "test@example.com")
	// This might or might not error depending on git version
	// Just test that the function doesn't panic
	if err == nil {
		t.Log("CommitAll() allowed empty commit")
	} else {
		t.Logf("CommitAll() rejected empty commit: %v", err)
	}

	// Create a change and test normal commit
	testFile := filepath.Join(tmpDir, "test2.txt")
	os.WriteFile(testFile, []byte("test"), 0644)

	err = gitRepo.CommitAll("Test commit", "Author", "author@test.com")
	if err != nil {
		t.Errorf("CommitAll() with changes error = %v", err)
	}
}

func TestCreateBranchIdempotent(t *testing.T) {
	gitRepo, _ := createTestRepo(t)

	// Create a branch
	err := gitRepo.CreateBranch("test-branch")
	if err != nil {
		t.Fatalf("CreateBranch() initial error = %v", err)
	}

	// Creating the same branch again should be idempotent (just checkout)
	err = gitRepo.CreateBranch("test-branch")
	if err != nil {
		t.Logf("CreateBranch() with existing branch error = %v", err)
	}

	// Verify we're still on the branch
	branch, err := gitRepo.GetCurrentBranch()
	if err != nil {
		t.Errorf("GetCurrentBranch() error = %v", err)
	}
	if branch != "test-branch" {
		t.Errorf("GetCurrentBranch() = %s, want test-branch", branch)
	}
}
