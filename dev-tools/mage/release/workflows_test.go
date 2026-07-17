// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package release

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestRunMajorMinorReleaseDryRunBranches(t *testing.T) {
	origMageUpdate := runMageUpdate
	runMageUpdate = func() error { return nil }
	t.Cleanup(func() { runMageUpdate = origMageUpdate })

	tmpDir := setupWorkflowTestRepo(t)

	origDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get cwd: %v", err)
	}
	defer func() {
		if err := os.Chdir(origDir); err != nil {
			t.Errorf("failed to restore cwd: %v", err)
		}
	}()
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatalf("failed to chdir: %v", err)
	}

	cfg := &ReleaseConfig{
		CurrentRelease:          "9.5.0",
		NextRelease:             "9.5.1",
		NextProjectMinorVersion: "9.6.0",
		NextProjectMinorBranch:  "9.6",
		BaseBranch:              "main",
		ReleaseBranch:           "9.5",
		DryRun:                  true,
		GitAuthorName:           "Test User",
		GitAuthorEmail:          "test@example.com",
	}

	if err := RunMajorMinorRelease(cfg); err != nil {
		t.Fatalf("RunMajorMinorRelease dry run failed: %v", err)
	}

	repo, err := OpenRepo(".")
	if err != nil {
		t.Fatalf("failed to open repo: %v", err)
	}

	wantBranches := []string{
		"main",
		"9.5",
		"ff-prep-main-9.5.0",
		"ff-release-9.5.0",
		"ff-prep-main-docs-9.6.0",
		"ff-prep-next-patch-9.5.1",
	}
	for _, branch := range wantBranches {
		exists, err := repo.BranchExists(branch)
		if err != nil {
			t.Fatalf("failed checking branch %s: %v", branch, err)
		}
		if !exists {
			t.Errorf("expected branch %s to exist after dry run", branch)
		}
	}

	assertGitShowContains(t, tmpDir, "ff-prep-main-9.5.0", "version/version.go", `defaultBeatVersion = "9.6.0"`)
	assertGitShowContains(t, tmpDir, "ff-prep-main-9.5.0", ".mergify.yml", "backport-9.5")

	assertGitShowContains(t, tmpDir, "ff-release-9.5.0", "version/version.go", `defaultBeatVersion = "9.5.0"`)
	assertGitShowContains(t, tmpDir, "ff-release-9.5.0", "version/docs/version.asciidoc", ":stack-version: 9.5.0")
	assertGitShowContains(t, tmpDir, "ff-release-9.5.0", "README.md", "/9.5/")

	// PR-C must not rewrite README /main/ → next minor branch.
	assertGitShowContains(t, tmpDir, "ff-prep-main-docs-9.6.0", "README.md", "/main/")
	assertGitShowNotContains(t, tmpDir, "ff-prep-main-docs-9.6.0", "README.md", "/9.6/")
	assertGitShowContains(t, tmpDir, "ff-prep-main-docs-9.6.0", "version/docs/version.asciidoc", ":stack-version: 9.6.0")

	assertGitShowContains(t, tmpDir, "ff-prep-next-patch-9.5.1", "version/version.go", `defaultBeatVersion = "9.5.1"`)
	assertGitShowContains(t, tmpDir, "ff-prep-next-patch-9.5.1", "version/docs/version.asciidoc", ":stack-version: 9.4.3")
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
		{name: "PR-C", labels: prCMainLabels(cfg.ReleaseBranch), want: mergeLabelAfterImages},
		{name: "PR-D", labels: prDNextPatchLabels(), want: mergeLabelAfterRelease},
	}
	for _, tc := range casesLabels {
		t.Run(tc.name+" labels", func(t *testing.T) {
			if !slices.Contains(tc.labels, tc.want) {
				t.Errorf("%s labels should include %q, got %v", tc.name, tc.want, tc.labels)
			}
		})
	}

	labelsA := prAMainLabels(cfg.ReleaseBranch)
	if !slices.Contains(labelsA, "backport-9.5") {
		t.Errorf("PR-A labels should include backport-9.5, got %v", labelsA)
	}
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
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v (%s)", args, err, out)
		}
	}
	runGit("branch", "9.5")

	origDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get cwd: %v", err)
	}
	defer func() {
		if err := os.Chdir(origDir); err != nil {
			t.Errorf("failed to restore cwd: %v", err)
		}
	}()
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatalf("failed to chdir: %v", err)
	}

	cfg := &ReleaseConfig{
		CurrentRelease: "9.5.1",
		LatestRelease:  "9.5.0",
		NextRelease:    "9.5.2",
		BaseBranch:     "main",
		ReleaseBranch:  "9.5",
		DryRun:         true,
		GitAuthorName:  "Test User",
		GitAuthorEmail: "test@example.com",
	}

	if err := RunPatchRelease(cfg); err != nil {
		t.Fatalf("RunPatchRelease dry run failed: %v", err)
	}

	repo, err := OpenRepo(".")
	if err != nil {
		t.Fatalf("failed to open repo: %v", err)
	}

	wantBranches := []string{
		"update-version-9.5.1",
		"update-docs-version-9.5.1",
		"ff-prep-next-patch-9.5.2",
	}
	for _, branch := range wantBranches {
		exists, err := repo.BranchExists(branch)
		if err != nil {
			t.Fatalf("failed checking branch %s: %v", branch, err)
		}
		if !exists {
			t.Errorf("expected branch %s to exist after dry run", branch)
		}
	}

	assertGitShowContains(t, tmpDir, "update-version-9.5.1", "version/version.go", `defaultBeatVersion = "9.5.1"`)
	assertGitShowContains(t, tmpDir, "update-docs-version-9.5.1", "version/docs/version.asciidoc", ":stack-version: 9.5.1")
	assertGitShowContains(t, tmpDir, "ff-prep-next-patch-9.5.2", "version/version.go", `defaultBeatVersion = "9.5.2"`)
}

func TestPatchPrepLabels(t *testing.T) {
	cases := []struct {
		name   string
		labels []string
		want   string
	}{
		{name: "PR-A version", labels: patchVersionPRLabels(), want: mergeLabelBeforeBuild},
		{name: "PR-B docs", labels: patchDocsPRLabelsWithMerge(), want: mergeLabelBeforeBuild},
		{name: "PR-D next", labels: prDNextPatchLabels(), want: mergeLabelAfterRelease},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if !slices.Contains(tc.labels, tc.want) {
				t.Errorf("%s labels should include %q, got %v", tc.name, tc.want, tc.labels)
			}
		})
	}

	docsLabels := patchDocsPRLabelsWithMerge()
	for _, want := range []string{"docs", "in progress", "release", "Team:Automation", "skip-changelog"} {
		if !slices.Contains(docsLabels, want) {
			t.Errorf("docs labels should include %q, got %v", want, docsLabels)
		}
	}
}

func assertGitShowContains(t *testing.T, dir, branch, file, want string) {
	t.Helper()
	out, err := exec.CommandContext(context.Background(), "git", "-C", dir, "show", branch+":"+file).CombinedOutput()
	if err != nil {
		t.Fatalf("git show %s:%s: %v (%s)", branch, file, err, out)
	}
	if !strings.Contains(string(out), want) {
		t.Errorf("%s:%s should contain %q, got:\n%s", branch, file, want, out)
	}
}

func assertGitShowNotContains(t *testing.T, dir, branch, file, forbid string) {
	t.Helper()
	out, err := exec.CommandContext(context.Background(), "git", "-C", dir, "show", branch+":"+file).CombinedOutput()
	if err != nil {
		t.Fatalf("git show %s:%s: %v (%s)", branch, file, err, out)
	}
	if strings.Contains(string(out), forbid) {
		t.Errorf("%s:%s should not contain %q, got:\n%s", branch, file, forbid, out)
	}
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
		if err := os.MkdirAll(filepath.Dir(fullPath), 0755); err != nil {
			t.Fatalf("failed to create dir for %s: %v", path, err)
		}
		if err := os.WriteFile(fullPath, []byte(content), 0644); err != nil {
			t.Fatalf("failed to write %s: %v", path, err)
		}
	}

	runGit("add", ".")
	runGit("commit", "-m", "initial commit")

	return tmpDir
}
