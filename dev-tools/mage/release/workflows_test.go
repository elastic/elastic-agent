// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package release

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRunMajorMinorReleaseDryRunBranches(t *testing.T) {
	origMageUpdate := runMageUpdate
	runMageUpdate = func() error { return nil }
	t.Cleanup(func() { runMageUpdate = origMageUpdate })

	origFetch := fetchLatestReleaseBefore
	fetchLatestReleaseBefore = func(token, owner, repo, current string) (string, error) {
		return "9.4.3", nil
	}
	t.Cleanup(func() { fetchLatestReleaseBefore = origFetch })

	tmpDir := setupWorkflowTestRepo(t)

	runGit := func(args ...string) {
		t.Helper()
		cmd := exec.CommandContext(context.Background(), "git", args...)
		cmd.Dir = tmpDir
		out, err := cmd.CombinedOutput()
		require.NoError(t, err, "git %v: %s", args, out)
	}
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "version/version.go"), []byte(`package version

const defaultBeatVersion = "9.5.0"
`), 0644), "failed to seed version.go")
	runGit("add", ".")
	runGit("commit", "-m", "seed main at 9.5.0")

	origDir, err := os.Getwd()
	require.NoError(t, err, "failed to get cwd")
	defer func() {
		require.NoError(t, os.Chdir(origDir), "failed to restore cwd")
	}()
	require.NoError(t, os.Chdir(tmpDir), "failed to chdir")

	cfg := &ReleaseConfig{
		CurrentRelease:          "9.5.0",
		LatestRelease:           "9.4.3",
		NextRelease:             "9.5.1",
		NextProjectMinorVersion: "9.6.0",
		NextProjectMinorBranch:  "9.6",
		BaseBranch:              "main",
		ReleaseBranch:           "9.5",
		DryRun:                  true,
		GitAuthorName:           "Test User",
		GitAuthorEmail:          "test@example.com",
	}

	require.NoError(t, RunMajorMinorRelease(cfg), "RunMajorMinorRelease dry run failed")

	repo, err := OpenRepo(".")
	require.NoError(t, err, "failed to open repo")

	wantBranches := []string{
		"main",
		"9.5",
		"ff-prep-main-9.5.0",
		"ff-release-9.5.0",
	}
	for _, branch := range wantBranches {
		exists, err := repo.BranchExists(branch)
		require.NoError(t, err, "failed checking branch %s", branch)
		require.True(t, exists, "expected branch %s to exist after dry run", branch)
	}
	docsBranchExists, err := repo.BranchExists("ff-prep-main-docs-9.6.0")
	require.NoError(t, err, "failed checking docs branch")
	require.False(t, docsBranchExists, "expected ff-prep-main-docs-9.6.0 not to exist; docs belong in PR-A")
	nextPatchExists, err := repo.BranchExists("ff-prep-next-patch-9.5.1")
	require.NoError(t, err, "failed checking next-patch branch")
	require.False(t, nextPatchExists, "expected ff-prep-next-patch-9.5.1 not to exist; next-patch is owned by RunPatchRelease")

	assertGitShowContains(t, tmpDir, "ff-prep-main-9.5.0", "version/version.go", `defaultBeatVersion = "9.6.0"`)
	assertGitShowContains(t, tmpDir, "ff-prep-main-9.5.0", ".mergify.yml", "backport-9.5")
	// PR-A includes next-minor docs/manifests (agent combines former PR-C).
	assertGitShowContains(t, tmpDir, "ff-prep-main-9.5.0", "README.md", "/main/")
	assertGitShowNotContains(t, tmpDir, "ff-prep-main-9.5.0", "README.md", "/9.6/")
	assertGitShowContains(t, tmpDir, "ff-prep-main-9.5.0", "version/docs/version.asciidoc", ":stack-version: 9.6.0")
	assertGitShowContains(t, tmpDir, "ff-prep-main-9.5.0", "version/docs/version.asciidoc", ":doc-branch: main")
	assertGitShowContains(t, tmpDir, "ff-prep-main-9.5.0", "deploy/kubernetes/elastic-agent-managed-kubernetes.yaml", "elastic-agent:9.6.0")

	assertGitShowContains(t, tmpDir, "ff-release-9.5.0", "version/version.go", `defaultBeatVersion = "9.5.0"`)
	assertGitShowContains(t, tmpDir, "ff-release-9.5.0", "version/docs/version.asciidoc", ":stack-version: 9.5.0")
	assertGitShowContains(t, tmpDir, "ff-release-9.5.0", "README.md", "/9.5/")
}

func TestRunMajorMinorReleaseRejectsMismatchedCurrentRelease(t *testing.T) {
	origMageUpdate := runMageUpdate
	runMageUpdate = func() error { return nil }
	t.Cleanup(func() { runMageUpdate = origMageUpdate })

	origFetch := fetchLatestReleaseBefore
	fetchLatestReleaseBefore = func(token, owner, repo, current string) (string, error) {
		return "9.4.3", nil
	}
	t.Cleanup(func() { fetchLatestReleaseBefore = origFetch })

	tmpDir := setupWorkflowTestRepo(t)

	origDir, err := os.Getwd()
	require.NoError(t, err, "failed to get cwd")
	defer func() {
		require.NoError(t, os.Chdir(origDir), "failed to restore cwd")
	}()
	require.NoError(t, os.Chdir(tmpDir), "failed to chdir")

	cfg := &ReleaseConfig{
		CurrentRelease:          "9.5.0",
		LatestRelease:           "9.4.3",
		NextRelease:             "9.5.1",
		NextProjectMinorVersion: "9.6.0",
		BaseBranch:              "main",
		ReleaseBranch:           "9.5",
		DryRun:                  true,
		GitAuthorName:           "Test User",
		GitAuthorEmail:          "test@example.com",
	}

	err = RunMajorMinorRelease(cfg)
	require.Error(t, err, "expected RunMajorMinorRelease to fail when CURRENT_RELEASE mismatches main version")
	require.ErrorContains(t, err, "does not match version on main")
}

func TestMajorMinorPrepLabels(t *testing.T) {
	cfg := &ReleaseConfig{
		CurrentRelease:          "9.5.0",
		NextRelease:             "9.5.1",
		NextProjectMinorVersion: "9.6.0",
		ReleaseBranch:           "9.5",
		BaseBranch:              "main",
	}

	casesLabels := []struct {
		name   string
		labels []string
		want   string
	}{
		{name: "PR-A", labels: prAMainLabels(cfg.ReleaseBranch), want: mergeLabelFFDay},
		{name: "PR-B", labels: prBReleaseLabels(), want: mergeLabelAfterBranch},
	}
	for _, tc := range casesLabels {
		t.Run(tc.name+" labels", func(t *testing.T) {
			require.Contains(t, tc.labels, tc.want, "%s labels should include %q, got %v", tc.name, tc.want, tc.labels)
		})
	}

	labelsA := prAMainLabels(cfg.ReleaseBranch)
	require.Contains(t, labelsA, "backport-9.5", "PR-A labels should include backport-9.5, got %v", labelsA)
	require.Contains(t, labelsA, "docs", "PR-A labels should include docs, got %v", labelsA)
}

func TestRunPatchReleaseDryRunBranches(t *testing.T) {
	origMageUpdate := runMageUpdate
	runMageUpdate = func() error { return nil }
	t.Cleanup(func() { runMageUpdate = origMageUpdate })

	tmpDir := setupWorkflowTestRepo(t)

	runGit := func(args ...string) {
		t.Helper()
		cmd := exec.CommandContext(context.Background(), "git", args...)
		cmd.Dir = tmpDir
		out, err := cmd.CombinedOutput()
		require.NoError(t, err, "git %v: %s", args, out)
	}
	runGit("branch", "9.5")
	runGit("checkout", "9.5")
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "version/version.go"), []byte(`package version

const defaultBeatVersion = "9.5.1"
`), 0644), "failed to seed version.go")
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "version/docs/version.asciidoc"), []byte(`:stack-version: 9.5.0
:doc-branch: 9.5
`), 0644), "failed to seed version.asciidoc")
	runGit("add", ".")
	runGit("commit", "-m", "seed 9.5 branch at 9.5.1")
	runGit("checkout", "main")

	origDir, err := os.Getwd()
	require.NoError(t, err, "failed to get cwd")
	defer func() {
		require.NoError(t, os.Chdir(origDir), "failed to restore cwd")
	}()
	require.NoError(t, os.Chdir(tmpDir), "failed to chdir")

	cfg := &ReleaseConfig{
		CurrentRelease: "9.5.1",
		LatestRelease:  "9.5.0",
		NextRelease:    "9.5.2",
		ReleaseBranch:  "9.5",
		DryRun:         true,
		GitAuthorName:  "Test User",
		GitAuthorEmail: "test@example.com",
	}

	require.NoError(t, RunPatchRelease(cfg), "RunPatchRelease dry run failed")

	repo, err := OpenRepo(".")
	require.NoError(t, err, "failed to open repo")

	wantBranches := []string{
		"9.5",
		"patch-release-9.5.1",
		"ff-prep-next-patch-9.5.2",
	}
	for _, branch := range wantBranches {
		exists, err := repo.BranchExists(branch)
		require.NoError(t, err, "failed checking branch %s", branch)
		require.True(t, exists, "expected branch %s to exist after dry run", branch)
	}

	// PR-A: docs only — version.go unchanged from release branch.
	assertGitShowContains(t, tmpDir, "patch-release-9.5.1", "version/version.go", `defaultBeatVersion = "9.5.1"`)
	assertGitShowContains(t, tmpDir, "patch-release-9.5.1", "version/docs/version.asciidoc", ":stack-version: 9.5.1")
	assertGitShowContains(t, tmpDir, "ff-prep-next-patch-9.5.2", "version/version.go", `defaultBeatVersion = "9.5.2"`)
}

func TestRunPatchReleaseRejectsMismatchedCurrentRelease(t *testing.T) {
	origMageUpdate := runMageUpdate
	runMageUpdate = func() error { return nil }
	t.Cleanup(func() { runMageUpdate = origMageUpdate })

	tmpDir := setupWorkflowTestRepo(t)
	runGit := func(args ...string) {
		t.Helper()
		cmd := exec.CommandContext(context.Background(), "git", args...)
		cmd.Dir = tmpDir
		out, err := cmd.CombinedOutput()
		require.NoError(t, err, "git %v: %s", args, out)
	}
	runGit("branch", "9.5")
	runGit("checkout", "9.5")
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "version/version.go"), []byte(`package version

const defaultBeatVersion = "9.5.1"
`), 0644), "failed to seed version.go")
	runGit("add", ".")
	runGit("commit", "-m", "seed version 9.5.1")
	runGit("checkout", "main")

	origDir, err := os.Getwd()
	require.NoError(t, err, "failed to get cwd")
	defer func() {
		require.NoError(t, os.Chdir(origDir), "failed to restore cwd")
	}()
	require.NoError(t, os.Chdir(tmpDir), "failed to chdir")

	cfg := &ReleaseConfig{
		CurrentRelease: "9.5.0",
		LatestRelease:  "9.4.3",
		NextRelease:    "9.5.1",
		ReleaseBranch:  "9.5",
		DryRun:         true,
		GitAuthorName:  "Test User",
		GitAuthorEmail: "test@example.com",
	}

	err = RunPatchRelease(cfg)
	require.Error(t, err, "expected RunPatchRelease to fail when CURRENT_RELEASE mismatches branch version")
	require.ErrorContains(t, err, "does not match version on branch")
}

func TestPatchPrepLabels(t *testing.T) {
	cases := []struct {
		name   string
		labels []string
		want   string
	}{
		{name: "PR-A patch", labels: patchBeforeBuildPRLabels(), want: mergeLabelBeforeBuild},
		{name: "PR-B next", labels: prDNextPatchLabels(), want: mergeLabelAfterRelease},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Contains(t, tc.labels, tc.want, "%s labels should include %q, got %v", tc.name, tc.want, tc.labels)
		})
	}

	patchLabels := patchBeforeBuildPRLabels()
	for _, want := range []string{"docs", "in progress", "release", "Team:Automation", "skip-changelog"} {
		require.Contains(t, patchLabels, want, "patch release labels should include %q, got %v", want, patchLabels)
	}
}

func assertGitShowContains(t *testing.T, dir, branch, file, want string) {
	t.Helper()
	out, err := exec.CommandContext(context.Background(), "git", "-C", dir, "show", branch+":"+file).CombinedOutput()
	require.NoError(t, err, "git show %s:%s: %s", branch, file, out)
	require.Contains(t, string(out), want, "%s:%s should contain %q, got:\n%s", branch, file, want, out)
}

func assertGitShowNotContains(t *testing.T, dir, branch, file, forbid string) {
	t.Helper()
	out, err := exec.CommandContext(context.Background(), "git", "-C", dir, "show", branch+":"+file).CombinedOutput()
	require.NoError(t, err, "git show %s:%s: %s", branch, file, out)
	require.NotContains(t, string(out), forbid, "%s:%s should not contain %q, got:\n%s", branch, file, forbid, out)
}

func setupWorkflowTestRepo(t *testing.T) string {
	t.Helper()
	tmpDir := t.TempDir()
	ctx := context.Background()

	runGit := func(args ...string) {
		t.Helper()
		cmd := exec.CommandContext(ctx, "git", args...)
		cmd.Dir = tmpDir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Skipf("git not available: %v (%s)", err, out)
		}
	}

	runGit("init", "-b", "main")
	runGit("config", "user.name", "Test User")
	runGit("config", "user.email", "test@example.com")

	files := map[string]string{
		"version/version.go": `package version

const defaultBeatVersion = "9.4.3"
`,
		"version/docs/version.asciidoc": `:stack-version: 9.4.3
:doc-branch: main
`,
		".mergify.yml": `pull_request_rules:
  - name: backport patches to 9.4 branch
    conditions:
      - merged
      - label=backport-9.4
    actions:
      backport:
        branches:
          - "9.4"
`,
		"deploy/kubernetes/elastic-agent-managed-kubernetes.yaml": `image: docker.elastic.co/elastic-agent/elastic-agent:9.4.3
`,
		"deploy/kubernetes/elastic-agent-standalone-kubernetes.yaml": `image: docker.elastic.co/elastic-agent/elastic-agent:9.4.3
# branch ref: main
`,
		"README.md": "# Elastic Agent\n\nDocs: https://www.elastic.co/guide/en/fleet/main/index.html\n",
	}

	for path, content := range files {
		fullPath := filepath.Join(tmpDir, path)
		require.NoError(t, os.MkdirAll(filepath.Dir(fullPath), 0755), "failed to create dir for %s", path)
		require.NoError(t, os.WriteFile(fullPath, []byte(content), 0644), "failed to write %s", path)
	}

	runGit("add", ".")
	runGit("commit", "-m", "initial commit")

	return tmpDir
}
