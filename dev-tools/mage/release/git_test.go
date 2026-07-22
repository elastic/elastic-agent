// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package release

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

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
	cmd := exec.CommandContext(t.Context(), "git", gitArgs...)
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

func TestIsSubmoduleIndexLockError(t *testing.T) {
	tests := []struct {
		name   string
		output string
		want   bool
	}{
		{
			name: "index.lock file exists",
			output: "fatal: Unable to create '/repo/.git/modules/beats/index.lock': File exists.\n" +
				"Another git process seems to be running",
			want: true,
		},
		{
			name:   "unrelated submodule failure",
			output: "fatal: remote error: upload-pack: not our ref abcdef",
			want:   false,
		},
		{
			name:   "empty",
			output: "",
			want:   false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isSubmoduleIndexLockError(tt.output); got != tt.want {
				t.Fatalf("isSubmoduleIndexLockError() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSyncSubmodulesRetriesIndexLock(t *testing.T) {
	gitRepo, parentDir, _, _ := createRepoWithSubmodule(t)

	lockPath := filepath.Join(parentDir, ".git", "modules", "beats", "index.lock")
	if err := os.WriteFile(lockPath, []byte{}, 0644); err != nil {
		t.Fatalf("failed to create index.lock: %v", err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		time.Sleep(300 * time.Millisecond)
		_ = os.Remove(lockPath)
	}()

	if err := gitRepo.SyncSubmodules(); err != nil {
		t.Fatalf("SyncSubmodules() error = %v", err)
	}
	<-done
}

func TestCheckoutBranchSwitchesSubmodulePins(t *testing.T) {
	gitRepo, parentDir, v2, v1 := createRepoWithSubmodule(t)

	if err := gitRepo.CreateBranch("9.6"); err != nil {
		t.Fatalf("CreateBranch(9.6) error = %v", err)
	}
	if err := gitRepo.CheckoutBranch("9.6"); err != nil {
		t.Fatalf("CheckoutBranch(9.6) initial error = %v", err)
	}
	runGit(t, filepath.Join(parentDir, "beats"), "checkout", v1.String())
	runGit(t, parentDir, "add", "beats")
	runGit(t, parentDir, "commit", "-m", "pin submodule to v1")

	if err := gitRepo.CheckoutBranch("main"); err != nil {
		t.Fatalf("CheckoutBranch(main) error = %v", err)
	}
	current := strings.TrimSpace(runGit(t, filepath.Join(parentDir, "beats"), "rev-parse", "HEAD"))
	if current != v2.String() {
		t.Fatalf("after main checkout submodule = %s, want %s", current, v2.String())
	}

	if err := gitRepo.CheckoutBranch("9.6"); err != nil {
		t.Fatalf("CheckoutBranch(9.6) error = %v", err)
	}
	current = strings.TrimSpace(runGit(t, filepath.Join(parentDir, "beats"), "rev-parse", "HEAD"))
	if current != v1.String() {
		t.Fatalf("after 9.6 checkout submodule = %s, want %s", current, v1.String())
	}

	if err := gitRepo.CheckoutBranch("main"); err != nil {
		t.Fatalf("CheckoutBranch(main) second error = %v", err)
	}
	current = strings.TrimSpace(runGit(t, filepath.Join(parentDir, "beats"), "rev-parse", "HEAD"))
	if current != v2.String() {
		t.Fatalf("after second main checkout submodule = %s, want %s", current, v2.String())
	}
	if status := gitStatusPorcelain(t, parentDir); status != "" {
		t.Fatalf("worktree dirty after branch switches:\n%s", status)
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

func TestHasCommitsAheadOf(t *testing.T) {
	tests := []struct {
		name     string
		setup    func(t *testing.T, dir, baseBranch string)
		want     bool
		wantErr  bool
		baseName string
	}{
		{
			name:     "equal tips",
			baseName: "base",
			setup: func(t *testing.T, dir, baseBranch string) {
				runGit(t, dir, "branch", baseBranch)
			},
			want: false,
		},
		{
			name:     "ahead of base",
			baseName: "base",
			setup: func(t *testing.T, dir, baseBranch string) {
				runGit(t, dir, "branch", baseBranch)
				writeAndCommit(t, dir, "feature.txt", "feature", "feature commit")
			},
			want: true,
		},
		{
			name:     "behind base",
			baseName: "base",
			setup: func(t *testing.T, dir, baseBranch string) {
				runGit(t, dir, "branch", baseBranch)
				runGit(t, dir, "checkout", baseBranch)
				writeAndCommit(t, dir, "base-only.txt", "base", "base commit")
				runGit(t, dir, "checkout", "-")
			},
			want: false,
		},
		{
			name:     "diverged from base",
			baseName: "base",
			setup: func(t *testing.T, dir, baseBranch string) {
				runGit(t, dir, "branch", baseBranch)
				writeAndCommit(t, dir, "feature.txt", "feature", "feature commit")
				runGit(t, dir, "checkout", baseBranch)
				writeAndCommit(t, dir, "base-only.txt", "base", "base commit")
				runGit(t, dir, "checkout", "-")
			},
			want: true,
		},
		{
			name:     "missing base branch",
			baseName: "does-not-exist",
			setup:    func(t *testing.T, dir, baseBranch string) {},
			want:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := initGitRepoForAheadTest(t)
			tt.setup(t, dir, tt.baseName)

			repo, err := OpenRepo(dir)
			if err != nil {
				t.Fatalf("OpenRepo failed: %v", err)
			}

			got, err := repo.HasCommitsAheadOf(tt.baseName)
			if tt.wantErr {
				if err == nil {
					t.Fatal("HasCommitsAheadOf() error = nil, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("HasCommitsAheadOf() unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("HasCommitsAheadOf() = %v, want %v", got, tt.want)
			}
		})
	}
}

func initGitRepoForAheadTest(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	ctx := context.Background()

	cmd := exec.CommandContext(ctx, "git", "init")
	cmd.Dir = dir
	if err := cmd.Run(); err != nil {
		t.Skipf("git not available: %v", err)
	}

	runGit(t, dir, "config", "user.name", "Test User")
	runGit(t, dir, "config", "user.email", "test@example.com")
	writeAndCommit(t, dir, "README", "initial", "initial commit")
	return dir
}

func writeAndCommit(t *testing.T, dir, filename, content, message string) {
	t.Helper()
	path := filepath.Join(dir, filename)
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write %s: %v", filename, err)
	}
	runGit(t, dir, "add", filename)
	runGit(t, dir, "commit", "-m", message)
}
