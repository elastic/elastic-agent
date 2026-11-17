// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package release

import (
	"context"
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/stretchr/testify/require"
)

func createTestRepo(t *testing.T) (*GitRepo, string) {
	t.Helper()

	tmpDir := t.TempDir()

	repo, err := git.PlainInit(tmpDir, false)
	require.NoError(t, err, "failed to init repo")

	w, err := repo.Worktree()
	require.NoError(t, err, "failed to get worktree")

	testFile := filepath.Join(tmpDir, "README.md")
	require.NoError(t, os.WriteFile(testFile, []byte("# Test Repo"), 0644), "failed to write test file")

	_, err = w.Add("README.md")
	require.NoError(t, err, "failed to add file")

	_, err = w.Commit("Initial commit", &git.CommitOptions{
		Author: &object.Signature{
			Name:  "Test User",
			Email: "test@example.com",
		},
	})
	require.NoError(t, err, "failed to create initial commit")

	headRef, err := repo.Head()
	require.NoError(t, err, "failed to get HEAD")

	mainRef := plumbing.NewHashReference(plumbing.NewBranchReferenceName("main"), headRef.Hash())
	require.NoError(t, repo.Storer.SetReference(mainRef), "failed to create main branch")
	require.NoError(t, w.Checkout(&git.CheckoutOptions{Branch: plumbing.NewBranchReferenceName("main")}), "failed to checkout main")
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
	require.NoError(t, err, "git %v in %s failed:\n%s", args, dir, string(output))
	return string(output)
}

func createRepoWithSubmodule(t *testing.T) (*GitRepo, string, plumbing.Hash, plumbing.Hash) {
	t.Helper()

	rootDir := t.TempDir()
	submoduleDir := filepath.Join(rootDir, "submodule")
	parentDir := filepath.Join(rootDir, "parent")

	require.NoError(t, os.Mkdir(submoduleDir, 0755), "failed to create submodule dir")
	require.NoError(t, os.Mkdir(parentDir, 0755), "failed to create parent dir")

	runGit(t, submoduleDir, "init")
	runGit(t, submoduleDir, "config", "user.email", "test@example.com")
	runGit(t, submoduleDir, "config", "user.name", "Test User")
	require.NoError(t, os.WriteFile(filepath.Join(submoduleDir, "README.md"), []byte("v1"), 0644), "failed to write submodule file")
	runGit(t, submoduleDir, "add", "README.md")
	runGit(t, submoduleDir, "commit", "-m", "submodule v1")
	firstCommit := strings.TrimSpace(runGit(t, submoduleDir, "rev-parse", "HEAD"))

	require.NoError(t, os.WriteFile(filepath.Join(submoduleDir, "README.md"), []byte("v2"), 0644), "failed to update submodule file")
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
	require.NoError(t, err, "OpenRepo() error")

	firstHash := plumbing.NewHash(firstCommit)
	secondHash := plumbing.NewHash(secondCommit)
	return gitRepo, parentDir, secondHash, firstHash
}

func TestSyncSubmodulesNoSubmodules(t *testing.T) {
	gitRepo, _ := createTestRepo(t)

	require.NoError(t, gitRepo.SyncSubmodules(), "SyncSubmodules() error")
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
			got := isSubmoduleIndexLockError(tt.output)
			require.Equal(t, tt.want, got, "isSubmoduleIndexLockError()")
		})
	}
}

func TestSyncSubmodulesRetriesIndexLock(t *testing.T) {
	gitRepo, parentDir, _, _ := createRepoWithSubmodule(t)

	lockPath := filepath.Join(parentDir, ".git", "modules", "beats", "index.lock")
	require.NoError(t, os.WriteFile(lockPath, []byte{}, 0644), "failed to create index.lock")

	done := make(chan struct{})
	go func() {
		defer close(done)
		time.Sleep(300 * time.Millisecond)
		_ = os.Remove(lockPath)
	}()

	require.NoError(t, gitRepo.SyncSubmodules(), "SyncSubmodules() error")
	<-done
}

func TestCheckoutBranchSwitchesSubmodulePins(t *testing.T) {
	gitRepo, parentDir, v2, v1 := createRepoWithSubmodule(t)

	require.NoError(t, gitRepo.CreateBranch("9.6"), "CreateBranch(9.6) error")
	require.NoError(t, gitRepo.CheckoutBranch("9.6"), "CheckoutBranch(9.6) initial error")
	runGit(t, filepath.Join(parentDir, "beats"), "checkout", v1.String())
	runGit(t, parentDir, "add", "beats")
	runGit(t, parentDir, "commit", "-m", "pin submodule to v1")

	require.NoError(t, gitRepo.CheckoutBranch("main"), "CheckoutBranch(main) error")
	current := strings.TrimSpace(runGit(t, filepath.Join(parentDir, "beats"), "rev-parse", "HEAD"))
	require.Equal(t, v2.String(), current, "after main checkout submodule")

	require.NoError(t, gitRepo.CheckoutBranch("9.6"), "CheckoutBranch(9.6) error")
	current = strings.TrimSpace(runGit(t, filepath.Join(parentDir, "beats"), "rev-parse", "HEAD"))
	require.Equal(t, v1.String(), current, "after 9.6 checkout submodule")

	require.NoError(t, gitRepo.CheckoutBranch("main"), "CheckoutBranch(main) second error")
	current = strings.TrimSpace(runGit(t, filepath.Join(parentDir, "beats"), "rev-parse", "HEAD"))
	require.Equal(t, v2.String(), current, "after second main checkout submodule")
	require.Empty(t, gitStatusPorcelain(t, parentDir), "worktree dirty after branch switches:\n%s", gitStatusPorcelain(t, parentDir))
}

func gitStatusPorcelain(t *testing.T, dir string) string {
	t.Helper()
	return strings.TrimSpace(runGit(t, dir, "status", "--porcelain"))
}

func TestCheckoutBranchResetsDirtySubmodule(t *testing.T) {
	gitRepo, parentDir, pinnedCommit, otherCommit := createRepoWithSubmodule(t)

	runGit(t, filepath.Join(parentDir, "beats"), "checkout", otherCommit.String())

	require.NotEmpty(t, gitStatusPorcelain(t, parentDir), "test setup invalid: submodule should be dirty before checkout")

	require.NoError(t, gitRepo.CreateBranch("9.7"), "CreateBranch() error")
	require.NoError(t, gitRepo.CheckoutBranch("9.7"), "CheckoutBranch() error")

	require.Empty(t, gitStatusPorcelain(t, parentDir), "CheckoutBranch() should leave a clean worktree, got status:\n%s", gitStatusPorcelain(t, parentDir))

	currentSubmoduleCommit := strings.TrimSpace(runGit(t, filepath.Join(parentDir, "beats"), "rev-parse", "HEAD"))
	require.Equal(t, pinnedCommit.String(), currentSubmoduleCommit, "submodule commit")
}

func TestOpenRepo(t *testing.T) {
	_, tmpDir := createTestRepo(t)

	gitRepo, err := OpenRepo(tmpDir)
	require.NoError(t, err, "OpenRepo() error")
	require.NotNil(t, gitRepo)
	require.NotNil(t, gitRepo.repo, "OpenRepo() returned nil repo")

	_, err = OpenRepo("/non/existent/path")
	require.Error(t, err, "OpenRepo() should fail for non-existent path")
}

func TestOpenRepoWithAlternateObjects(t *testing.T) {
	_, source := createTestRepo(t)
	assertReferenceCloneIsClean := func(t *testing.T) {
		t.Helper()
		clone := filepath.Join(t.TempDir(), "checkout")
		runGit(t, source, "clone", "--no-local", "--reference", source, source, clone)

		repo, err := OpenRepo(clone)
		require.NoError(t, err)
		clean, err := repo.IsClean()
		require.NoError(t, err)
		require.True(t, clean, "IsClean() = %v, %v; want true, nil", clean, err)
	}
	t.Run("reference clone with loose objects", func(t *testing.T) {
		assertReferenceCloneIsClean(t)
	})
	t.Run("reference clone with packed objects", func(t *testing.T) {
		runGit(t, source, "repack", "-a", "-d")
		runGit(t, source, "prune-packed")
		assertReferenceCloneIsClean(t)
	})
}

func TestCreateBranch(t *testing.T) {
	gitRepo, _ := createTestRepo(t)

	require.NoError(t, gitRepo.CreateBranch("9.4"), "CreateBranch() error")
	require.NoError(t, gitRepo.CheckoutBranch("9.4"), "CheckoutBranch() error")

	currentBranch, err := gitRepo.GetCurrentBranch()
	require.NoError(t, err, "GetCurrentBranch() error")
	require.Equal(t, "9.4", currentBranch)
}

func TestEnsureBranchFrom(t *testing.T) {
	gitRepo, tmpDir := createTestRepo(t)

	require.NoError(t, gitRepo.CreateBranch("feature"), "CreateBranch(feature) error")
	require.NoError(t, gitRepo.CheckoutBranch("feature"), "CheckoutBranch(feature) error")

	featureFile := filepath.Join(tmpDir, "feature.txt")
	require.NoError(t, os.WriteFile(featureFile, []byte("feature work"), 0644), "failed to write feature file")
	_, err := gitRepo.CommitAll("feature commit", "Test Author", "test@example.com")
	require.NoError(t, err, "CommitAll() error")

	headOnFeature, err := gitRepo.repo.Head()
	require.NoError(t, err, "failed to get HEAD on feature branch")

	require.NoError(t, gitRepo.EnsureBranchFrom("main", "9.5"), "EnsureBranchFrom() error")

	headOnRelease, err := gitRepo.repo.Head()
	require.NoError(t, err, "failed to get HEAD on release branch")

	currentBranch, err := gitRepo.GetCurrentBranch()
	require.NoError(t, err, "GetCurrentBranch() error")
	require.Equal(t, "9.5", currentBranch)

	require.NoError(t, gitRepo.CheckoutBranch("main"), "CheckoutBranch(main) error")
	headOnMain, err := gitRepo.repo.Head()
	require.NoError(t, err, "failed to get HEAD on main")

	require.Equal(t, headOnMain.Hash(), headOnRelease.Hash(), "release branch should be created from main, not from feature branch HEAD")
	require.NotEqual(t, headOnMain.Hash(), headOnFeature.Hash(), "test setup invalid: feature branch should have commits ahead of main")
}

func TestCommitAllWithSubmoduleDirectory(t *testing.T) {
	gitRepo, tmpDir := createTestRepo(t)

	changeFile := filepath.Join(tmpDir, "change.txt")
	require.NoError(t, os.WriteFile(changeFile, []byte("release changes"), 0644), "failed to write change file")

	beatsDir := filepath.Join(tmpDir, "beats")
	require.NoError(t, os.Mkdir(beatsDir, 0755), "failed to create beats dir")
	require.NoError(t, os.WriteFile(filepath.Join(beatsDir, "README.md"), []byte("beats"), 0644), "failed to write beats file")

	committed, err := gitRepo.CommitAll("Release commit", "Test Author", "test@example.com")
	require.NoError(t, err, "CommitAll() error")
	require.True(t, committed, "CommitAll() should report a commit was created")

	ref, err := gitRepo.repo.Head()
	require.NoError(t, err, "failed to get HEAD")

	commit, err := gitRepo.repo.CommitObject(ref.Hash())
	require.NoError(t, err, "failed to get commit")

	tree, err := commit.Tree()
	require.NoError(t, err, "failed to get tree")

	_, err = tree.File("change.txt")
	require.NoError(t, err, "CommitAll() did not commit change.txt")
}

func TestCommitAll(t *testing.T) {
	gitRepo, tmpDir := createTestRepo(t)

	testFile := filepath.Join(tmpDir, "test.txt")
	require.NoError(t, os.WriteFile(testFile, []byte("test content"), 0644), "failed to write test file")

	committed, err := gitRepo.CommitAll("Test commit", "Test Author", "test@example.com")
	require.NoError(t, err, "CommitAll() error")
	require.True(t, committed, "CommitAll() should report a commit was created")

	ref, err := gitRepo.repo.Head()
	require.NoError(t, err, "failed to get HEAD")

	commit, err := gitRepo.repo.CommitObject(ref.Hash())
	require.NoError(t, err, "failed to get commit")
	require.Equal(t, "Test commit", commit.Message, "CommitAll() commit message")
}

func TestGetCurrentBranch(t *testing.T) {
	gitRepo, _ := createTestRepo(t)

	branch, err := gitRepo.GetCurrentBranch()
	require.NoError(t, err, "GetCurrentBranch() error")
	require.Equal(t, "main", branch)

	testBranch := "test-branch"
	require.NoError(t, gitRepo.CreateBranch(testBranch), "CreateBranch() error")
	require.NoError(t, gitRepo.CheckoutBranch(testBranch), "CheckoutBranch() error")

	branch, err = gitRepo.GetCurrentBranch()
	require.NoError(t, err, "GetCurrentBranch() error")
	require.Equal(t, testBranch, branch)
}

func TestGitHTTPSAuthExtraHeader(t *testing.T) {
	got := gitHTTPSAuthExtraHeader("test-token")
	wantPrefix := "Authorization: Basic "
	require.True(t, strings.HasPrefix(got, wantPrefix), "gitHTTPSAuthExtraHeader() = %q, want prefix %q", got, wantPrefix)
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(got, wantPrefix))
	require.NoError(t, err)
	require.Equal(t, "x-access-token:test-token", string(decoded))
	require.NotContains(t, got, "Bearer")
}

func TestGitPushEnv(t *testing.T) {
	env := gitPushEnv([]string{"PATH=/usr/bin"}, "test-token")
	wantHeader := gitHTTPSAuthExtraHeader("test-token")
	got := map[string]string{}
	for _, entry := range env {
		key, value, ok := strings.Cut(entry, "=")
		require.True(t, ok, "malformed env entry %q", entry)
		got[key] = value
	}
	require.Equal(t, "/usr/bin", got["PATH"])
	require.Equal(t, "0", got["GIT_TERMINAL_PROMPT"])
	require.Equal(t, "2", got["GIT_CONFIG_COUNT"])
	require.Equal(t, "http.https://github.com/.extraHeader", got["GIT_CONFIG_KEY_0"])
	require.Empty(t, got["GIT_CONFIG_VALUE_0"])
	require.Equal(t, "http.https://github.com/.extraHeader", got["GIT_CONFIG_KEY_1"])
	require.Equal(t, wantHeader, got["GIT_CONFIG_VALUE_1"])
}

func TestPushRequiresToken(t *testing.T) {
	gitRepo, _ := createTestRepo(t)

	err := gitRepo.Push("origin", "")
	require.Error(t, err, "Push() should fail without a token")
}

func TestPushRequiresOriginRemote(t *testing.T) {
	gitRepo, _ := createTestRepo(t)

	err := gitRepo.Push("upstream", "test-token")
	require.Error(t, err, "Push() should reject non-origin remotes")
	require.ErrorContains(t, err, "only supports origin")
}

func TestPushToLocalRemote(t *testing.T) {
	gitRepo, workDir := createTestRepo(t)

	bareDir := t.TempDir()
	_, err := git.PlainInit(bareDir, true)
	require.NoError(t, err)
	remoteURL := "file://" + bareDir
	require.NoError(t, gitRepo.SetRemoteURL("origin", remoteURL))

	branch := "release-9.6"
	require.NoError(t, gitRepo.CreateBranch(branch))
	require.NoError(t, gitRepo.CheckoutBranch(branch))

	// Token is unused for file:// remotes but required by Push.
	require.NoError(t, gitRepo.Push("origin", "test-token"))

	remoteHeads := runGit(t, workDir, "ls-remote", "--heads", "origin", branch)
	require.Contains(t, remoteHeads, "refs/heads/"+branch)
}

func TestGithubHTTPSPushURL(t *testing.T) {
	tests := []struct {
		name      string
		in        string
		want      string
		rewritten bool
	}{
		{
			name:      "scp ssh",
			in:        "git@github.com:elastic/elastic-agent.git",
			want:      "https://github.com/elastic/elastic-agent.git",
			rewritten: true,
		},
		{
			name:      "ssh scheme",
			in:        "ssh://git@github.com/elastic/elastic-agent.git",
			want:      "https://github.com/elastic/elastic-agent.git",
			rewritten: true,
		},
		{
			name:      "ssh scheme with port",
			in:        "ssh://git@github.com:22/elastic/elastic-agent.git",
			want:      "https://github.com/elastic/elastic-agent.git",
			rewritten: true,
		},
		{
			name:      "https unchanged",
			in:        "https://github.com/elastic/elastic-agent.git",
			want:      "https://github.com/elastic/elastic-agent.git",
			rewritten: false,
		},
		{
			name:      "non-github ssh unchanged",
			in:        "git@gitlab.com:group/repo.git",
			want:      "git@gitlab.com:group/repo.git",
			rewritten: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, rewritten := githubHTTPSPushURL(tt.in)
			require.Equal(t, tt.want, got, "githubHTTPSPushURL(%q) URL", tt.in)
			require.Equal(t, tt.rewritten, rewritten, "githubHTTPSPushURL(%q) rewritten", tt.in)
		})
	}
}

func TestEnsureHTTPSRemote(t *testing.T) {
	t.Run("rewrites ssh to https", func(t *testing.T) {
		gitRepo, _ := createTestRepo(t)
		require.NoError(t, gitRepo.SetRemoteURL("origin", "git@github.com:elastic/elastic-agent.git"), "SetRemoteURL() error")
		require.NoError(t, gitRepo.ensureHTTPSRemote("origin"), "ensureHTTPSRemote() error")
		remote, err := gitRepo.repo.Remote("origin")
		require.NoError(t, err, "Remote() error")
		require.Equal(t, "https://github.com/elastic/elastic-agent.git", remote.Config().URLs[0], "origin URL")
	})

	t.Run("leaves https unchanged", func(t *testing.T) {
		gitRepo, _ := createTestRepo(t)
		want := "https://github.com/elastic/elastic-agent.git"
		require.NoError(t, gitRepo.SetRemoteURL("origin", want), "SetRemoteURL() error")
		require.NoError(t, gitRepo.ensureHTTPSRemote("origin"), "ensureHTTPSRemote() error")
		remote, err := gitRepo.repo.Remote("origin")
		require.NoError(t, err, "Remote() error")
		require.Equal(t, want, remote.Config().URLs[0], "origin URL")
	})

	t.Run("rejects non-https remote", func(t *testing.T) {
		gitRepo, _ := createTestRepo(t)
		require.NoError(t, gitRepo.SetRemoteURL("origin", "git@gitlab.com:group/repo.git"), "SetRemoteURL() error")
		err := gitRepo.ensureHTTPSRemote("origin")
		require.Error(t, err, "ensureHTTPSRemote() expected error for non-HTTPS remote")
		require.ErrorContains(t, err, "not HTTPS")
	})
}

func TestSetRemoteURL(t *testing.T) {
	gitRepo, _ := createTestRepo(t)

	require.NoError(t, gitRepo.SetRemoteURL("origin", "https://github.com/test/repo.git"), "SetRemoteURL() error")

	remote, err := gitRepo.repo.Remote("origin")
	require.NoError(t, err, "Failed to get remote")
	require.NotEmpty(t, remote.Config().URLs)
	require.Equal(t, "https://github.com/test/repo.git", remote.Config().URLs[0], "SetRemoteURL() URL")
}

func TestCommitAllIdempotent(t *testing.T) {
	gitRepo, tmpDir := createTestRepo(t)

	testFile := filepath.Join(tmpDir, "test.txt")
	require.NoError(t, os.WriteFile(testFile, []byte("test content"), 0644), "failed to write test file")

	committed, err := gitRepo.CommitAll("Test commit", "Test Author", "test@example.com")
	require.NoError(t, err, "CommitAll() first call error")
	require.True(t, committed, "CommitAll() first call should create a commit")

	headBefore, err := gitRepo.repo.Head()
	require.NoError(t, err, "failed to get HEAD before second commit")

	committed, err = gitRepo.CommitAll("Test commit", "Test Author", "test@example.com")
	require.NoError(t, err, "CommitAll() second call error")
	require.False(t, committed, "CommitAll() is not idempotent - second call created a new commit")

	headAfter, err := gitRepo.repo.Head()
	require.NoError(t, err, "failed to get HEAD after second commit")
	require.Equal(t, headBefore.Hash(), headAfter.Hash(), "CommitAll() is not idempotent - HEAD changed on second call")
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
			require.NoError(t, err, "OpenRepo failed")

			got, err := repo.HasCommitsAheadOf(tt.baseName)
			if tt.wantErr {
				require.Error(t, err, "HasCommitsAheadOf() error = nil, want error")
				return
			}
			require.NoError(t, err, "HasCommitsAheadOf() unexpected error")
			require.Equal(t, tt.want, got, "HasCommitsAheadOf()")
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
	require.NoError(t, os.WriteFile(path, []byte(content), 0644), "write %s", filename)
	runGit(t, dir, "add", filename)
	runGit(t, dir, "commit", "-m", message)
}
