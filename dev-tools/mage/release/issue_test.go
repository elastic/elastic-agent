// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package release

import (
	"strings"
	"testing"

	"github.com/google/go-github/v93/github"
	"github.com/stretchr/testify/require"

	devtools "github.com/elastic/elastic-agent/dev-tools/mage"
)

func TestReleaseIssueTitle(t *testing.T) {
	got := releaseIssueTitle("9.4.1")
	require.Equal(t, "[RELEASE 9.4.1] Instructions & Checklist", got)
}

func TestIsMajorMinorRelease(t *testing.T) {
	minor, err := devtools.ParseReleaseVersion("9.5.0")
	require.NoError(t, err)
	require.True(t, isMajorMinorRelease(minor), "expected 9.5.0 to be treated as major/minor")
	patch, err := devtools.ParseReleaseVersion("9.5.1")
	require.NoError(t, err)
	require.False(t, isMajorMinorRelease(patch), "expected 9.5.1 not to be treated as major/minor")
}

func TestVersionMentioned(t *testing.T) {
	require.True(t, versionMentioned("[Release] Update version to 9.4.1", "9.4.1"), "exact version in title should match")
	require.False(t, versionMentioned("[Release] Update version to 9.4.10", "9.4.1"), "9.4.1 must not match 9.4.10")
	require.True(t, versionMentioned("Add Elastic Agent 9.4.1 release notes", "9.4.1"), "docs PR title should match")
}

func TestBuildReleaseIssueBodyMajorMinorSection(t *testing.T) {
	minorBody := buildReleaseIssueBody("9.5.0", true, nil, nil)
	require.Contains(t, minorBody, "### Only For Major/Minor Releases")
	require.Contains(t, minorBody, globalReleaseTrackerURL)
	require.Contains(t, minorBody, "elastic/elastic-agent/labels/release")

	patchBody := buildReleaseIssueBody("9.5.1", false, nil, nil)
	require.NotContains(t, patchBody, "### Only For Major/Minor Releases")
}

func TestMergePRURLsSortsAndDedups(t *testing.T) {
	got := mergePRURLs(
		[]string{"https://github.com/elastic/elastic-agent/pull/20", "https://github.com/elastic/elastic-agent/pull/10"},
		[]string{"https://github.com/elastic/elastic-agent/pull/10", "https://github.com/elastic/elastic-agent/pull/15"},
	)
	want := []string{
		"https://github.com/elastic/elastic-agent/pull/10",
		"https://github.com/elastic/elastic-agent/pull/15",
		"https://github.com/elastic/elastic-agent/pull/20",
	}
	require.Equal(t, want, got)
}

func TestExtractPRCheckboxes(t *testing.T) {
	body := `
## PRs

- [x] https://github.com/elastic/elastic-agent/pull/10
- [ ] https://github.com/elastic/elastic-agent/pull/11
`
	got := extractPRCheckboxes(body)
	require.True(t, got["https://github.com/elastic/elastic-agent/pull/10"], "checked PR should be true")
	require.False(t, got["https://github.com/elastic/elastic-agent/pull/11"], "unchecked PR should be false")
}

func TestMergeReleaseIssueBodyAddsMissingPRsAndPreservesChecks(t *testing.T) {
	existing := `Global tracker: https://github.com/elastic/ingest-dev/issues/8866

# Release Checklist

- [x] Find the Elastic Agent release PRs

## PRs

- [x] https://github.com/elastic/elastic-agent/pull/10
- [ ] https://github.com/elastic/elastic-agent/pull/11
`
	updated, changed := mergeReleaseIssueBody(existing, "9.4.1", false, []string{
		"https://github.com/elastic/elastic-agent/pull/11",
		"https://github.com/elastic/elastic-agent/pull/12",
	})
	require.True(t, changed, "adding a missing PR should mark the body changed")
	require.Contains(t, updated, "- [x] https://github.com/elastic/elastic-agent/pull/10")
	require.Contains(t, updated, "- [ ] https://github.com/elastic/elastic-agent/pull/11")
	require.Contains(t, updated, "- [ ] https://github.com/elastic/elastic-agent/pull/12")
	require.Contains(t, updated, "- [x] Find the Elastic Agent release PRs")

	_, changedAgain := mergeReleaseIssueBody(updated, "9.4.1", false, []string{
		"https://github.com/elastic/elastic-agent/pull/10",
		"https://github.com/elastic/elastic-agent/pull/11",
		"https://github.com/elastic/elastic-agent/pull/12",
	})
	require.False(t, changedAgain, "second merge with same PRs should be a no-op")
}

func TestMergeReleaseIssueBodyAddsTrackerWhenMissing(t *testing.T) {
	existing := `# Release Checklist

## PRs

- [ ] https://github.com/elastic/elastic-agent/pull/10
`
	updated, changed := mergeReleaseIssueBody(existing, "9.4.1", false, []string{"https://github.com/elastic/elastic-agent/pull/10"})
	require.True(t, changed, "missing global tracker should trigger an update")
	require.True(t, strings.HasPrefix(strings.TrimSpace(updated), "Global tracker: "+globalReleaseTrackerURL))
}

func TestEnsureReleaseIssueTrackerDryRun(t *testing.T) {
	cfg := &ReleaseConfig{
		NextRelease: "9.4.1",
		DryRun:      true,
	}
	pr := &github.PullRequest{HTMLURL: new("https://github.com/elastic/elastic-agent/pull/99")}
	require.NoError(t, EnsureReleaseIssueTracker(cfg, []*github.PullRequest{pr}))
}

func TestWarnEnsureReleaseIssueTrackerDoesNotPanicOnError(t *testing.T) {
	warnEnsureReleaseIssueTracker(&ReleaseConfig{}, nil)
}

func TestPrURLsFromPullRequestsSkipsNil(t *testing.T) {
	got := prURLsFromPullRequests([]*github.PullRequest{
		nil,
		{HTMLURL: new("https://github.com/elastic/elastic-agent/pull/1")},
	})
	require.Equal(t, []string{"https://github.com/elastic/elastic-agent/pull/1"}, got)
}
