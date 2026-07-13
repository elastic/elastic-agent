// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package release

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
)

func createTestRepo(t *testing.T) (*GitRepo, string) {
	t.Helper()

	tmpDir := t.TempDir()

	repo, err := git.PlainInit(tmpDir, false)
	if err != nil {
		t.Fatalf("failed to init repo: %v", err)
	}

	w, err := repo.Worktree()
	if err != nil {
		t.Fatalf("failed to get worktree: %v", err)
	}

	testFile := filepath.Join(tmpDir, "README.md")
	err = os.WriteFile(testFile, []byte("# Test Repo"), 0644)
	if err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

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

	headRef, err := repo.Head()
	if err != nil {
		t.Fatalf("failed to get HEAD: %v", err)
	}

	mainRef := plumbing.NewHashReference(plumbing.NewBranchReferenceName("main"), headRef.Hash())
	if err := repo.Storer.SetReference(mainRef); err != nil {
		t.Fatalf("failed to create main branch: %v", err)
	}
	if err := w.Checkout(&git.CheckoutOptions{Branch: plumbing.NewBranchReferenceName("main")}); err != nil {
		t.Fatalf("failed to checkout main: %v", err)
	}
	_ = repo.Storer.RemoveReference(plumbing.NewBranchReferenceName("master"))

	gitRepo := &GitRepo{repo: repo, path: tmpDir}
	return gitRepo, tmpDir
}

func runGit(t *testing.T, dir string, args ...string) string {
	t.Helper()

	gitArgs := append([]string{"-c", "protocol.file.allow=always"}, args...)
	cmd := exec.Command("git", gitArgs...)
	cmd.Dir = dir
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v in %s failed: %v\n%s", args, dir, err, string(output))
	}
	return string(output)
}

func createRepoWithSubmodule(t *testing.T) (*GitRepo, string, plumbing.Hash, plumbing.Hash) {
	t.Helper()

	rootDir := t.TempDir()
	submoduleDir := filepath.Join(rootDir, "submodule")
	parentDir := filepath.Join(rootDir, "parent")

	if err := os.Mkdir(submoduleDir, 0755); err != nil {
		t.Fatalf("failed to create submodule dir: %v", err)
	}
	if err := os.Mkdir(parentDir, 0755); err != nil {
		t.Fatalf("failed to create parent dir: %v", err)
	}

	runGit(t, submoduleDir, "init")
	runGit(t, submoduleDir, "config", "user.email", "test@example.com")
	runGit(t, submoduleDir, "config", "user.name", "Test User")
	if err := os.WriteFile(filepath.Join(submoduleDir, "README.md"), []byte("v1"), 0644); err != nil {
		t.Fatalf("failed to write submodule file: %v", err)
	}
	runGit(t, submoduleDir, "add", "README.md")
	runGit(t, submoduleDir, "commit", "-m", "submodule v1")
	firstCommit := strings.TrimSpace(runGit(t, submoduleDir, "rev-parse", "HEAD"))

	if err := os.WriteFile(filepath.Join(submoduleDir, "README.md"), []byte("v2"), 0644); err != nil {
		t.Fatalf("failed to update submodule file: %v", err)
	}
	runGit(t, submoduleDir, "add", "README.md")
	runGit(t, submoduleDir, "commit", "-m", "submodule v2")
	secondCommit := strings.TrimSpace(runGit(t, submoduleDir, "rev-parse", "HEAD"))

	runGit(t, parentDir, "init")
	runGit(t, parentDir, "config", "user.email", "test@example.com")
	runGit(t, parentDir, "config", "user.name", "Test User")
	runGit(t, parentDir, "submodule", "add", submoduleDir, "beats")
	runGit(t, parentDir, "commit", "-m", "pin submodule to v2")
	runGit(t, parentDir, "branch", "-M", "main")

	gitRepo, err := OpenRepo(parentDir)
	if err != nil {
		t.Fatalf("OpenRepo() error = %v", err)
	}

	firstHash := plumbing.NewHash(firstCommit)
	secondHash := plumbing.NewHash(secondCommit)
	return gitRepo, parentDir, secondHash, firstHash
}

func TestSyncSubmodulesNoSubmodules(t *testing.T) {
	gitRepo, _ := createTestRepo(t)

	if err := gitRepo.SyncSubmodules(); err != nil {
		t.Fatalf("SyncSubmodules() error = %v", err)
	}
}

func gitStatusPorcelain(t *testing.T, dir string) string {
	t.Helper()
	return strings.TrimSpace(runGit(t, dir, "status", "--porcelain"))
}

func TestCheckoutBranchResetsDirtySubmodule(t *testing.T) {
	gitRepo, parentDir, pinnedCommit, otherCommit := createRepoWithSubmodule(t)

	runGit(t, filepath.Join(parentDir, "beats"), "checkout", otherCommit.String())

	if gitStatusPorcelain(t, parentDir) == "" {
		t.Fatal("test setup invalid: submodule should be dirty before checkout")
	}

	if err := gitRepo.CreateBranch("9.7"); err != nil {
		t.Fatalf("CreateBranch() error = %v", err)
	}
	if err := gitRepo.CheckoutBranch("9.7"); err != nil {
		t.Fatalf("CheckoutBranch() error = %v", err)
	}

	if gitStatusPorcelain(t, parentDir) != "" {
		t.Fatalf("CheckoutBranch() should leave a clean worktree, got status:\n%s", gitStatusPorcelain(t, parentDir))
	}

	currentSubmoduleCommit := strings.TrimSpace(runGit(t, filepath.Join(parentDir, "beats"), "rev-parse", "HEAD"))
	if currentSubmoduleCommit != pinnedCommit.String() {
		t.Fatalf("submodule commit = %s, want %s", currentSubmoduleCommit, pinnedCommit.String())
	}
}

func TestOpenRepo(t *testing.T) {
	_, tmpDir := createTestRepo(t)

	gitRepo, err := OpenRepo(tmpDir)
	if err != nil {
		t.Errorf("OpenRepo() error = %v", err)
		return
	}

	if gitRepo == nil || gitRepo.repo == nil {
		t.Error("OpenRepo() returned nil repo")
	}

	_, err = OpenRepo("/non/existent/path")
	if err == nil {
		t.Error("OpenRepo() should fail for non-existent path")
	}
}

func TestCreateBranch(t *testing.T) {
	gitRepo, _ := createTestRepo(t)

	err := gitRepo.CreateBranch("9.4")
	if err != nil {
		t.Fatalf("CreateBranch() error = %v", err)
	}

	err = gitRepo.CheckoutBranch("9.4")
	if err != nil {
		t.Fatalf("CheckoutBranch() error = %v", err)
	}

	currentBranch, err := gitRepo.GetCurrentBranch()
	if err != nil {
		t.Fatalf("GetCurrentBranch() error = %v", err)
	}
	if currentBranch != "9.4" {
		t.Errorf("GetCurrentBranch() = %s, want 9.4", currentBranch)
	}
}

func TestEnsureBranchFrom(t *testing.T) {
	gitRepo, tmpDir := createTestRepo(t)

	if err := gitRepo.CreateBranch("feature"); err != nil {
		t.Fatalf("CreateBranch(feature) error = %v", err)
	}
	if err := gitRepo.CheckoutBranch("feature"); err != nil {
		t.Fatalf("CheckoutBranch(feature) error = %v", err)
	}

	featureFile := filepath.Join(tmpDir, "feature.txt")
	if err := os.WriteFile(featureFile, []byte("feature work"), 0644); err != nil {
		t.Fatalf("failed to write feature file: %v", err)
	}
	if _, err := gitRepo.CommitAll("feature commit", "Test Author", "test@example.com"); err != nil {
		t.Fatalf("CommitAll() error = %v", err)
	}

	headOnFeature, err := gitRepo.repo.Head()
	if err != nil {
		t.Fatalf("failed to get HEAD on feature branch: %v", err)
	}

	if err := gitRepo.EnsureBranchFrom("main", "9.5"); err != nil {
		t.Fatalf("EnsureBranchFrom() error = %v", err)
	}

	headOnRelease, err := gitRepo.repo.Head()
	if err != nil {
		t.Fatalf("failed to get HEAD on release branch: %v", err)
	}

	currentBranch, err := gitRepo.GetCurrentBranch()
	if err != nil {
		t.Fatalf("GetCurrentBranch() error = %v", err)
	}
	if currentBranch != "9.5" {
		t.Errorf("GetCurrentBranch() = %s, want 9.5", currentBranch)
	}

	if err := gitRepo.CheckoutBranch("main"); err != nil {
		t.Fatalf("CheckoutBranch(main) error = %v", err)
	}
	headOnMain, err := gitRepo.repo.Head()
	if err != nil {
		t.Fatalf("failed to get HEAD on main: %v", err)
	}

	if headOnRelease.Hash() != headOnMain.Hash() {
		t.Error("release branch should be created from main, not from feature branch HEAD")
	}
	if headOnFeature.Hash() == headOnMain.Hash() {
		t.Fatal("test setup invalid: feature branch should have commits ahead of main")
	}
}

func TestCommitAllWithSubmoduleDirectory(t *testing.T) {
	gitRepo, tmpDir := createTestRepo(t)

	changeFile := filepath.Join(tmpDir, "change.txt")
	if err := os.WriteFile(changeFile, []byte("release changes"), 0644); err != nil {
		t.Fatalf("failed to write change file: %v", err)
	}

	beatsDir := filepath.Join(tmpDir, "beats")
	if err := os.Mkdir(beatsDir, 0755); err != nil {
		t.Fatalf("failed to create beats dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(beatsDir, "README.md"), []byte("beats"), 0644); err != nil {
		t.Fatalf("failed to write beats file: %v", err)
	}

	committed, err := gitRepo.CommitAll("Release commit", "Test Author", "test@example.com")
	if err != nil {
		t.Fatalf("CommitAll() error = %v", err)
	}
	if !committed {
		t.Fatal("CommitAll() should report a commit was created")
	}

	ref, err := gitRepo.repo.Head()
	if err != nil {
		t.Fatalf("failed to get HEAD: %v", err)
	}

	commit, err := gitRepo.repo.CommitObject(ref.Hash())
	if err != nil {
		t.Fatalf("failed to get commit: %v", err)
	}

	tree, err := commit.Tree()
	if err != nil {
		t.Fatalf("failed to get tree: %v", err)
	}

	if _, err := tree.File("change.txt"); err != nil {
		t.Fatalf("CommitAll() did not commit change.txt: %v", err)
	}
}

func TestCommitAll(t *testing.T) {
	gitRepo, tmpDir := createTestRepo(t)

	testFile := filepath.Join(tmpDir, "test.txt")
	err := os.WriteFile(testFile, []byte("test content"), 0644)
	if err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	committed, err := gitRepo.CommitAll("Test commit", "Test Author", "test@example.com")
	if err != nil {
		t.Errorf("CommitAll() error = %v", err)
		return
	}
	if !committed {
		t.Fatal("CommitAll() should report a commit was created")
	}

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
}

func TestGetCurrentBranch(t *testing.T) {
	gitRepo, _ := createTestRepo(t)

	branch, err := gitRepo.GetCurrentBranch()
	if err != nil {
		t.Errorf("GetCurrentBranch() error = %v", err)
		return
	}
	if branch != "main" {
		t.Errorf("GetCurrentBranch() = %s, want main", branch)
	}

	testBranch := "test-branch"
	err = gitRepo.CreateBranch(testBranch)
	if err != nil {
		t.Fatalf("CreateBranch() error = %v", err)
	}
	err = gitRepo.CheckoutBranch(testBranch)
	if err != nil {
		t.Fatalf("CheckoutBranch() error = %v", err)
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

func TestPushRequiresToken(t *testing.T) {
	gitRepo, _ := createTestRepo(t)

	oldToken := os.Getenv("GITHUB_TOKEN")
	os.Unsetenv("GITHUB_TOKEN")
	t.Cleanup(func() {
		if oldToken != "" {
			os.Setenv("GITHUB_TOKEN", oldToken)
		}
	})

	err := gitRepo.Push("origin")
	if err == nil {
		t.Error("Push() should fail without GITHUB_TOKEN, got nil error")
	}
}

func TestSetRemoteURL(t *testing.T) {
	gitRepo, _ := createTestRepo(t)

	err := gitRepo.SetRemoteURL("origin", "https://github.com/test/repo.git")
	if err != nil {
		t.Errorf("SetRemoteURL() error = %v", err)
		return
	}

	remote, err := gitRepo.repo.Remote("origin")
	if err != nil {
		t.Errorf("Failed to get remote: %v", err)
		return
	}
	if len(remote.Config().URLs) == 0 || remote.Config().URLs[0] != "https://github.com/test/repo.git" {
		t.Errorf("SetRemoteURL() URL = %v, want https://github.com/test/repo.git", remote.Config().URLs)
	}
}

func TestCommitAllIdempotent(t *testing.T) {
	gitRepo, tmpDir := createTestRepo(t)

	testFile := filepath.Join(tmpDir, "test.txt")
	err := os.WriteFile(testFile, []byte("test content"), 0644)
	if err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	committed, err := gitRepo.CommitAll("Test commit", "Test Author", "test@example.com")
	if err != nil {
		t.Fatalf("CommitAll() first call error = %v", err)
	}
	if !committed {
		t.Fatal("CommitAll() first call should create a commit")
	}

	headBefore, err := gitRepo.repo.Head()
	if err != nil {
		t.Fatalf("failed to get HEAD before second commit: %v", err)
	}

	committed, err = gitRepo.CommitAll("Test commit", "Test Author", "test@example.com")
	if err != nil {
		t.Errorf("CommitAll() second call error = %v", err)
	}
	if committed {
		t.Error("CommitAll() is not idempotent - second call created a new commit")
	}

	headAfter, err := gitRepo.repo.Head()
	if err != nil {
		t.Fatalf("failed to get HEAD after second commit: %v", err)
	}
	if headBefore.Hash() != headAfter.Hash() {
		t.Error("CommitAll() is not idempotent - HEAD changed on second call")
	}
}
