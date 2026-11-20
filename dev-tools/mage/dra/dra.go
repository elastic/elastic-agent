// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

// Package dra resolves the DRA (Daily Releasable Artifacts) builds that
// elastic-agent-package is assembled from, and merges their manifests into the
// single manifest the packaging code consumes through MANIFEST_URL.
//
// elastic-agent-package is unusual among DRA products: it does not build the
// artifacts it publishes from its own source alone, it assembles them from the
// DRA builds of several other products (elastic-agent-core, fleet-server,
// apm-server, ...). Deciding which products those are, which build of each is
// current, and what the resulting manifest looks like is packaging logic, so it
// lives here next to the packaging code and runs the same way locally as in CI:
//
//	mage dra:mergeManifests
//	MANIFEST_PATH=build/dra/agent-artifacts-merged.json AGENT_CORE_SOURCE=manifest mage package
//
// What surrounds it in CI — reading and writing GCS, talking to the Buildkite
// API — stays in .buildkite/scripts, because none of it can run locally anyway.
// The contract between the two is the merged manifest: its build_id is a
// content hash of the dependency builds (see DependencySetID), which is what
// the poller script uses to tell whether these inputs were already built.
package dra

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// Workflow is a DRA release workflow. It selects which artifacts host the
// dependency builds are read from and which version string keys a "latest"
// pointer.
type Workflow string

const (
	// WorkflowSnapshot is the continuously published snapshot workflow.
	WorkflowSnapshot Workflow = "snapshot"
	// WorkflowStaging is the release-candidate workflow.
	WorkflowStaging Workflow = "staging"
)

const (
	snapshotArtifactsHost = "artifacts-snapshot.elastic.co"
	stagingArtifactsHost  = "artifacts-staging.elastic.co"

	snapshotSuffix = "-SNAPSHOT"
)

// ParseWorkflow validates s and returns the matching Workflow.
func ParseWorkflow(s string) (Workflow, error) {
	switch w := Workflow(s); w {
	case WorkflowSnapshot, WorkflowStaging:
		return w, nil
	default:
		return "", fmt.Errorf("unknown DRA workflow %q, expected %q or %q", s, WorkflowSnapshot, WorkflowStaging)
	}
}

// ArtifactsHost returns the host serving per-project DRA artifacts for the workflow.
func (w Workflow) ArtifactsHost() string {
	if w == WorkflowStaging {
		return stagingArtifactsHost
	}
	return snapshotArtifactsHost
}

// QualifyVersion renders the version string DRA uses to key a project's "latest"
// pointer: "9.7.0-SNAPSHOT" for the snapshot workflow, "9.7.0" for staging.
func (w Workflow) QualifyVersion(version string) string {
	version = strings.TrimSuffix(strings.TrimSpace(version), snapshotSuffix)
	if w == WorkflowSnapshot {
		return version + snapshotSuffix
	}
	return version
}

// LatestPointerKey is the last path segment of a project's "latest" pointer.
//
// DRA publishes two keys for the same build and they agree:
//
//	https://artifacts-snapshot.elastic.co/beats/latest/master.json
//	https://artifacts-snapshot.elastic.co/beats/latest/9.7.0-SNAPSHOT.json
//
// The branch key is what CI uses, because it follows a branch across version
// bumps on its own. Note that the default branch is published as "master" —
// there is no main.json. The version key is the fallback for anything with no
// branch of its own in DRA, which is every feature branch, and is what makes a
// local run on one resolve the same builds CI would.
type LatestPointerKey string

// releaseBranch matches the branches DRA publishes a pointer for, besides the
// default branch: "9.6", "8.19", "9.x".
var releaseBranch = regexp.MustCompile(`^\d+\.(\d+|x)$`)

// BranchPointerKey returns the key DRA publishes for a branch, and whether the
// branch has one at all.
func BranchPointerKey(branch string) (LatestPointerKey, bool) {
	switch branch = strings.TrimSpace(branch); {
	case branch == "main", branch == "master":
		// Dependency teams publish their default branch as "master".
		return "master", true
	case releaseBranch.MatchString(branch):
		return LatestPointerKey(branch), true
	default:
		return "", false
	}
}

// VersionPointerKey returns the key for an exact stack version.
func (w Workflow) VersionPointerKey(version string) LatestPointerKey {
	return LatestPointerKey(w.QualifyVersion(version))
}

// LatestBuild is the "latest" pointer DRA publishes per project at
// https://<artifacts host>/<project>/latest/<key>.json.
type LatestBuild struct {
	Version     string `json:"version"`
	BuildID     string `json:"build_id"`
	ManifestURL string `json:"manifest_url"`
	SummaryURL  string `json:"summary_url"`
}

// ErrNoLatestBuild is returned when a project has no published build for the
// requested version. It is expected for a product that has not built yet on a
// freshly opened release branch, so callers may choose to tolerate it.
var ErrNoLatestBuild = errors.New("no published DRA build for this project and version")

// ArtifactsClient reads DRA pointers and manifests over HTTP.
type ArtifactsClient struct {
	// BaseURL is the artifacts host root, without a trailing slash.
	BaseURL string
	// HTTP is the client used for all requests. Defaults to a client with a
	// 60s timeout when nil.
	HTTP *http.Client
	// RetryDelays controls how often and how long a failed request is retried.
	// Defaults to defaultRetryDelays when nil.
	RetryDelays []time.Duration
}

// NewArtifactsClient returns a client reading the artifacts host of the workflow.
func NewArtifactsClient(w Workflow) *ArtifactsClient {
	return &ArtifactsClient{BaseURL: "https://" + w.ArtifactsHost()}
}

var defaultRetryDelays = []time.Duration{time.Second, 3 * time.Second, 10 * time.Second}

// LatestBuild returns the current DRA build of project under the given pointer
// key, or ErrNoLatestBuild if there is none.
func (c *ArtifactsClient) LatestBuild(ctx context.Context, project string, key LatestPointerKey) (LatestBuild, error) {
	pointerURL := fmt.Sprintf("%s/%s/latest/%s.json",
		strings.TrimSuffix(c.BaseURL, "/"), url.PathEscape(project), url.PathEscape(string(key)))

	body, err := c.get(ctx, pointerURL)
	if errors.Is(err, errNotFound) {
		return LatestBuild{}, fmt.Errorf("%w: %s %s (%s)", ErrNoLatestBuild, project, key, pointerURL)
	}
	if err != nil {
		return LatestBuild{}, fmt.Errorf("fetching latest pointer for %s: %w", project, err)
	}

	var latest LatestBuild
	if err := json.Unmarshal(body, &latest); err != nil {
		return LatestBuild{}, fmt.Errorf("decoding latest pointer for %s from %s: %w", project, pointerURL, err)
	}
	if latest.ManifestURL == "" {
		return LatestBuild{}, fmt.Errorf("latest pointer for %s at %s has no manifest_url", project, pointerURL)
	}
	return latest, nil
}

// RawManifest downloads a DRA manifest verbatim. The bytes are kept raw so that
// merging preserves fields this repository does not model.
func (c *ArtifactsClient) RawManifest(ctx context.Context, manifestURL string) ([]byte, error) {
	body, err := c.get(ctx, manifestURL)
	if err != nil {
		return nil, fmt.Errorf("fetching manifest %s: %w", manifestURL, err)
	}
	return body, nil
}

var errNotFound = errors.New("not found")

func (c *ArtifactsClient) get(ctx context.Context, rawURL string) ([]byte, error) {
	delays := c.RetryDelays
	if delays == nil {
		delays = defaultRetryDelays
	}

	var lastErr error
	for attempt := 0; ; attempt++ {
		body, err := c.doGet(ctx, rawURL)
		if err == nil {
			return body, nil
		}
		// A 404 is an answer, not a transient failure.
		if errors.Is(err, errNotFound) || ctx.Err() != nil {
			return nil, err
		}
		lastErr = err
		if attempt >= len(delays) {
			return nil, lastErr
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(delays[attempt]):
		}
	}
}

func (c *ArtifactsClient) doGet(ctx context.Context, rawURL string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("composing request for %s: %w", rawURL, err)
	}

	httpClient := c.HTTP
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 60 * time.Second}
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", rawURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("GET %s: %w", rawURL, errNotFound)
	}
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("GET %s: unexpected status %s", rawURL, resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading body of %s: %w", rawURL, err)
	}
	return body, nil
}
