// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package dra

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseWorkflow(t *testing.T) {
	for _, tc := range []struct {
		input   string
		want    Workflow
		wantErr bool
	}{
		{input: "snapshot", want: WorkflowSnapshot},
		{input: "staging", want: WorkflowStaging},
		{input: "", wantErr: true},
		{input: "release", wantErr: true},
		{input: "SNAPSHOT", wantErr: true},
	} {
		t.Run(tc.input, func(t *testing.T) {
			got, err := ParseWorkflow(tc.input)
			if tc.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestWorkflowQualifyVersion(t *testing.T) {
	// A version pointer is keyed by the exact qualified version, so getting the
	// suffix wrong means every lookup 404s.
	assert.Equal(t, "9.7.0-SNAPSHOT", WorkflowSnapshot.QualifyVersion("9.7.0"))
	assert.Equal(t, "9.7.0-SNAPSHOT", WorkflowSnapshot.QualifyVersion("9.7.0-SNAPSHOT"))
	assert.Equal(t, "9.7.0-SNAPSHOT", WorkflowSnapshot.QualifyVersion(" 9.7.0 "))
	assert.Equal(t, "9.6.0", WorkflowStaging.QualifyVersion("9.6.0"))
	assert.Equal(t, "9.6.0", WorkflowStaging.QualifyVersion("9.6.0-SNAPSHOT"))
}

func TestWorkflowArtifactsHost(t *testing.T) {
	assert.Equal(t, "artifacts-snapshot.elastic.co", WorkflowSnapshot.ArtifactsHost())
	assert.Equal(t, "artifacts-staging.elastic.co", WorkflowStaging.ArtifactsHost())
}

func TestArtifactsClientLatestBuild(t *testing.T) {
	const pointer = `{
	  "version": "9.7.0-SNAPSHOT",
	  "build_id": "9.7.0-f269df44",
	  "manifest_url": "https://artifacts-snapshot.elastic.co/beats/9.7.0-f269df44/manifest-9.7.0-SNAPSHOT.json",
	  "summary_url": "https://artifacts-snapshot.elastic.co/beats/9.7.0-f269df44/summary-9.7.0-SNAPSHOT.html"
	}`

	var requested string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requested = r.URL.Path
		if r.URL.Path != "/fleet-server/latest/9.7.0-SNAPSHOT.json" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(pointer))
	}))
	defer server.Close()

	client := &ArtifactsClient{BaseURL: server.URL}

	latest, err := client.LatestBuild(context.Background(), "fleet-server", "9.7.0-SNAPSHOT")
	require.NoError(t, err)
	assert.Equal(t, "/fleet-server/latest/9.7.0-SNAPSHOT.json", requested)
	assert.Equal(t, "9.7.0-f269df44", latest.BuildID)
	assert.Equal(t, "9.7.0-SNAPSHOT", latest.Version)
	assert.NotEmpty(t, latest.ManifestURL)

	_, err = client.LatestBuild(context.Background(), "apm-server", "9.7.0-SNAPSHOT")
	assert.ErrorIs(t, err, ErrNoLatestBuild)
}

func TestArtifactsClientRetriesTransientFailures(t *testing.T) {
	var attempts int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts < 3 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		_, _ = w.Write([]byte(`{"build_id":"9.7.0-abc","manifest_url":"https://example.invalid/m.json"}`))
	}))
	defer server.Close()

	client := &ArtifactsClient{BaseURL: server.URL, RetryDelays: []time.Duration{0, 0, 0}}
	latest, err := client.LatestBuild(context.Background(), "fleet-server", "9.7.0-SNAPSHOT")
	require.NoError(t, err)
	assert.Equal(t, 3, attempts)
	assert.Equal(t, "9.7.0-abc", latest.BuildID)
}

func TestArtifactsClientDoesNotRetryNotFound(t *testing.T) {
	var attempts int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		http.NotFound(w, r)
	}))
	defer server.Close()

	client := &ArtifactsClient{BaseURL: server.URL, RetryDelays: []time.Duration{0, 0, 0}}
	_, err := client.LatestBuild(context.Background(), "fleet-server", "9.7.0-SNAPSHOT")
	assert.ErrorIs(t, err, ErrNoLatestBuild)
	assert.Equal(t, 1, attempts, "a 404 is an answer, not a transient failure")
}

func TestArtifactsClientRejectsPointerWithoutManifestURL(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"version":"9.7.0-SNAPSHOT","build_id":"9.7.0-abc"}`))
	}))
	defer server.Close()

	client := &ArtifactsClient{BaseURL: server.URL}
	_, err := client.LatestBuild(context.Background(), "fleet-server", "9.7.0-SNAPSHOT")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no manifest_url")
}

func TestBranchPointerKey(t *testing.T) {
	for name, tc := range map[string]struct {
		branch        string
		want          LatestPointerKey
		wantPublished bool
	}{
		// Dependency teams publish their default branch as "master"; there is
		// no main.json, which is what made the original poller resolve nothing.
		"main":           {branch: "main", want: "master", wantPublished: true},
		"master":         {branch: "master", want: "master", wantPublished: true},
		"minor":          {branch: "9.6", want: "9.6", wantPublished: true},
		"two-digit":      {branch: "8.19", want: "8.19", wantPublished: true},
		"x branch":       {branch: "9.x", want: "9.x", wantPublished: true},
		"padded":         {branch: " 9.6 ", want: "9.6", wantPublished: true},
		"feature branch": {branch: "swiatekm/some-fix", wantPublished: false},
		"patch branch":   {branch: "9.6.1", wantPublished: false},
		"empty":          {branch: "", wantPublished: false},
	} {
		t.Run(name, func(t *testing.T) {
			key, published := BranchPointerKey(tc.branch)
			assert.Equal(t, tc.wantPublished, published)
			if tc.wantPublished {
				assert.Equal(t, tc.want, key)
			}
		})
	}
}

func TestVersionPointerKey(t *testing.T) {
	assert.Equal(t, LatestPointerKey("9.7.0-SNAPSHOT"), WorkflowSnapshot.VersionPointerKey("9.7.0"))
	assert.Equal(t, LatestPointerKey("9.6.0"), WorkflowStaging.VersionPointerKey("9.6.0"))
}
