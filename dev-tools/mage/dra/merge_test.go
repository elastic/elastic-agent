// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package dra

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/dev-tools/mage/manifest"
	"github.com/elastic/elastic-agent/dev-tools/packaging"
)

// fakeDRA serves "latest" pointers and manifests for a set of projects.
type fakeDRA struct {
	server *httptest.Server
	// buildIDs maps project name to the build ID its pointer advertises.
	buildIDs map[string]string
	// extraProjects maps a project name to additional project names its
	// manifest also describes.
	extraProjects map[string][]string
}

func newFakeDRA(t *testing.T, buildIDs map[string]string) *fakeDRA {
	t.Helper()
	f := &fakeDRA{buildIDs: buildIDs, extraProjects: map[string][]string{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		project, kind := splitFakePath(r.URL.Path)
		buildID, known := f.buildIDs[project]
		if !known {
			http.NotFound(w, r)
			return
		}

		switch kind {
		case "latest":
			_ = json.NewEncoder(w).Encode(LatestBuild{
				Version:     "9.7.0-SNAPSHOT",
				BuildID:     buildID,
				ManifestURL: f.server.URL + "/" + project + "/manifest.json",
			})
		case "manifest":
			projects := map[string]any{
				project: map[string]any{
					"branch":      "main",
					"commit_hash": "deadbeef",
					"packages":    map[string]any{project + "-9.7.0-SNAPSHOT-linux-x86_64.tar.gz": map[string]any{"url": "https://example.invalid/pkg"}},
				},
			}
			for _, extra := range f.extraProjects[project] {
				projects[extra] = map[string]any{"branch": "main", "packages": map[string]any{}}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"version":  "9.7.0-SNAPSHOT",
				"build_id": buildID,
				"projects": projects,
			})
		default:
			http.NotFound(w, r)
		}
	})
	f.server = httptest.NewServer(mux)
	t.Cleanup(f.server.Close)
	return f
}

// splitFakePath maps /<project>/latest/<version>.json and
// /<project>/manifest.json onto the project and the kind of document asked for.
func splitFakePath(path string) (project, kind string) {
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if len(parts) < 2 {
		return "", ""
	}
	switch {
	case len(parts) == 2 && parts[1] == "manifest.json":
		return parts[0], "manifest"
	case len(parts) == 3 && parts[1] == "latest":
		return parts[0], "latest"
	default:
		return parts[0], ""
	}
}

func (f *fakeDRA) client() *ArtifactsClient {
	return &ArtifactsClient{BaseURL: f.server.URL}
}

func TestResolveDependencies(t *testing.T) {
	fake := newFakeDRA(t, map[string]string{
		"fleet-server":       "9.7.0-aaa",
		"elastic-agent-core": "9.7.0-bbb",
	})

	resolved, missing, err := ResolveDependencies(context.Background(), fake.client(), LatestPointerKey("9.7.0-SNAPSHOT"),
		[]string{"elastic-agent-core", "fleet-server", "cloud-defend"})
	require.NoError(t, err)

	assert.Equal(t, []string{"cloud-defend"}, missing)
	require.Len(t, resolved, 2)
	assert.Equal(t, "elastic-agent-core", resolved[0].Project)
	assert.Equal(t, "9.7.0-bbb", resolved[0].BuildID)
	assert.Equal(t, "fleet-server", resolved[1].Project)
}

func TestResolveDependenciesFailsWhenNothingIsPublished(t *testing.T) {
	fake := newFakeDRA(t, map[string]string{})
	_, _, err := ResolveDependencies(context.Background(), fake.client(), LatestPointerKey("9.7.0-SNAPSHOT"), []string{"fleet-server"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no dependency has a published")
}

func TestDependencySetID(t *testing.T) {
	a := []DependencyBuild{{Project: "fleet-server", BuildID: "1"}, {Project: "apm-server", BuildID: "2"}}
	reordered := []DependencyBuild{{Project: "apm-server", BuildID: "2"}, {Project: "fleet-server", BuildID: "1"}}

	id := DependencySetID("9.7.0-SNAPSHOT", a)
	assert.Equal(t, id, DependencySetID("9.7.0-SNAPSHOT", reordered), "ordering must not change the id")
	assert.True(t, len(id) > len("9.7.0-SNAPSHOT"))
	assert.Equal(t, "9.7.0-SNAPSHOT-", id[:len("9.7.0-SNAPSHOT-")])

	moved := []DependencyBuild{{Project: "fleet-server", BuildID: "1"}, {Project: "apm-server", BuildID: "3"}}
	assert.NotEqual(t, id, DependencySetID("9.7.0-SNAPSHOT", moved), "a moved dependency must change the id")

	dropped := []DependencyBuild{{Project: "fleet-server", BuildID: "1"}}
	assert.NotEqual(t, id, DependencySetID("9.7.0-SNAPSHOT", dropped), "a dropped dependency must change the id")

	assert.NotEqual(t, id, DependencySetID("9.6.0-SNAPSHOT", a), "the version must be part of the id")
}

func TestBuildMergedManifest(t *testing.T) {
	fake := newFakeDRA(t, map[string]string{
		"fleet-server":       "9.7.0-aaa",
		"elastic-agent-core": "9.7.0-bbb",
	})
	// A dependency's manifest may describe more than the project we asked for.
	fake.extraProjects["fleet-server"] = []string{"fleet-server-ui"}

	resolved, _, err := ResolveDependencies(context.Background(), fake.client(), LatestPointerKey("9.7.0-SNAPSHOT"),
		[]string{"elastic-agent-core", "fleet-server"})
	require.NoError(t, err)

	merged, err := BuildMergedManifest(context.Background(), fake.client(), WorkflowSnapshot, "main", "9.7.0-SNAPSHOT", resolved)
	require.NoError(t, err)

	assert.Equal(t, "9.7.0-SNAPSHOT", merged.Version)
	assert.Equal(t, "main", merged.Branch)
	assert.Equal(t, "snapshot", merged.Workflow)
	assert.Equal(t, DependencySetID("9.7.0-SNAPSHOT", resolved), merged.BuildID)
	assert.ElementsMatch(t, []string{"elastic-agent-core", "fleet-server", "fleet-server-ui"}, keysOf(merged.Projects))
	assert.Len(t, merged.DependencyBuilds, 2)

	require.NoError(t, merged.Validate([]string{"elastic-agent-core", "fleet-server"}))
	assert.Error(t, merged.Validate([]string{"cloudbeat"}))

	// The merged document must round-trip through the type the packaging code
	// parses manifests with.
	raw, err := merged.MarshalIndent()
	require.NoError(t, err)
	var build manifest.Build
	require.NoError(t, json.Unmarshal(raw, &build))
	assert.Equal(t, "9.7.0-SNAPSHOT", build.Version)
	assert.Contains(t, build.Projects, "fleet-server")
	assert.Equal(t, "deadbeef", build.Projects["fleet-server"].CommitHash)
	assert.Contains(t, build.Projects["fleet-server"].Packages, "fleet-server-9.7.0-SNAPSHOT-linux-x86_64.tar.gz")
}

func TestBuildMergedManifestRejectsProjectCollisions(t *testing.T) {
	fake := newFakeDRA(t, map[string]string{
		"fleet-server": "9.7.0-aaa",
		"apm-server":   "9.7.0-bbb",
	})
	// Both dependencies claim to publish the same project.
	fake.extraProjects["fleet-server"] = []string{"shared"}
	fake.extraProjects["apm-server"] = []string{"shared"}

	resolved, _, err := ResolveDependencies(context.Background(), fake.client(), LatestPointerKey("9.7.0-SNAPSHOT"),
		[]string{"apm-server", "fleet-server"})
	require.NoError(t, err)

	_, err = BuildMergedManifest(context.Background(), fake.client(), WorkflowSnapshot, "main", "9.7.0-SNAPSHOT", resolved)
	require.Error(t, err)
	assert.Contains(t, err.Error(), `project "shared" is published by both`)
}

// TestDependenciesMatchPackagingComponents pins the contract the whole poller
// rests on: the dependency list is whatever packages.yml declares.
func TestDependenciesMatchPackagingComponents(t *testing.T) {
	deps, err := Dependencies()
	require.NoError(t, err)

	components, err := packaging.Components()
	require.NoError(t, err)

	for _, component := range components {
		assert.Contains(t, deps, component.ProjectName,
			"component %s/%s declares a project the poller does not watch", component.ProjectName, component.BinaryName)
	}
	assert.Contains(t, deps, "elastic-agent-core")
	assert.True(t, isSorted(deps))
}

func keysOf(m map[string]json.RawMessage) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func isSorted(values []string) bool {
	for i := 1; i < len(values); i++ {
		if values[i-1] > values[i] {
			return false
		}
	}
	return true
}

func TestStackVersion(t *testing.T) {
	t.Run("all dependencies agree", func(t *testing.T) {
		version, disagreeing, err := StackVersion([]DependencyBuild{
			{Project: "apm-server", Version: "9.7.0-SNAPSHOT"},
			{Project: "fleet-server", Version: "9.7.0-SNAPSHOT"},
		})
		require.NoError(t, err)
		assert.Equal(t, "9.7.0-SNAPSHOT", version)
		assert.Empty(t, disagreeing)
	})

	t.Run("elastic-agent-core wins a disagreement", func(t *testing.T) {
		// What a version bump in flight looks like: this repository has moved,
		// some dependencies have not.
		version, disagreeing, err := StackVersion([]DependencyBuild{
			{Project: "apm-server", Version: "9.7.0-SNAPSHOT"},
			{Project: AgentCoreProject, Version: "9.8.0-SNAPSHOT"},
			{Project: "fleet-server", Version: "9.7.0-SNAPSHOT"},
		})
		require.NoError(t, err)
		assert.Equal(t, "9.8.0-SNAPSHOT", version)
		assert.ElementsMatch(t, []string{"apm-server=9.7.0-SNAPSHOT", "fleet-server=9.7.0-SNAPSHOT"}, disagreeing)
	})

	t.Run("falls back to the first dependency", func(t *testing.T) {
		version, _, err := StackVersion([]DependencyBuild{{Project: "apm-server", Version: "9.7.0-SNAPSHOT"}})
		require.NoError(t, err)
		assert.Equal(t, "9.7.0-SNAPSHOT", version)
	})

	t.Run("rejects an empty set", func(t *testing.T) {
		_, _, err := StackVersion(nil)
		assert.Error(t, err)
	})
}
