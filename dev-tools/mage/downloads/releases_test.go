// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package downloads

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetSnapshotArtifactVersion(t *testing.T) {
	t.Run("Positive: parses commit has and returns full version", func(t *testing.T) {
		mockResponse := `{
			"version" : "8.8.3-SNAPSHOT",
			"build_id" : "8.8.3-b1d8691a",
			"manifest_url" : "https://artifacts-snapshot.elastic.co/beats/8.8.3-b1d8691a/manifest-8.8.3-SNAPSHOT.json",
			"summary_url" : "https://artifacts-snapshot.elastic.co/beats/8.8.3-b1d8691a/summary-8.8.3-SNAPSHOT.html"
		}`

		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			fmt.Fprintln(w, mockResponse)
		}))
		defer mockServer.Close()

		mockURL := mockServer.URL + "/beats/latest/8.8.3-SNAPSHOT.json"
		artifactsSnapshot := newArtifactsSnapshotCustom(mockURL)
		version, err := artifactsSnapshot.GetSnapshotArtifactVersion("beats", "8.8.3-SNAPSHOT")
		assert.NoError(t, err, "Expected no error")
		assert.Equal(t, "8.8.3-b1d8691a-SNAPSHOT", version, "Expected version to match")
	})

	t.Run("Negative: Invalid json response from server", func(t *testing.T) {
		mockResponse := `sdf{
			"ver" : "8.8.3-SNAPSHOT",
			"bui" : "8.8.3-b1d8691a",
			"manifest_url" : "https://artifacts-snapshot.elastic.co/beats/8.8.3-b1d8691a/manifest-8.8.3-SNAPSHOT.json",
			"summary_url" : "https://artifacts-snapshot.elastic.co/beats/8.8.3-b1d8691a/summary-8.8.3-SNAPSHOT.html"
		}`

		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			fmt.Fprintln(w, mockResponse)
		}))
		defer mockServer.Close()

		mockURL := mockServer.URL + "/beats/latest/8.8.3-SNAPSHOT.json"
		artifactsSnapshot := newArtifactsSnapshotCustom(mockURL)
		version, err := artifactsSnapshot.GetSnapshotArtifactVersion("beats", "8.8.3-SNAPSHOT")
		assert.ErrorContains(t, err, "could not parse the response body")
		assert.Empty(t, version)
	})

	t.Run("Negative: Unexpected build_id format", func(t *testing.T) {
		mockResponse := `{
			"version" : "8.8.3-SNAPSHOT",
			"build_id" : "bd8691a",
			"manifest_url" : "https://artifacts-snapshot.elastic.co/beats/8.8.3-b1d8691a/manifest-8.8.3-SNAPSHOT.json",
			"summary_url" : "https://artifacts-snapshot.elastic.co/beats/8.8.3-b1d8691a/summary-8.8.3-SNAPSHOT.html"
		}`

		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			fmt.Fprintln(w, mockResponse)
		}))
		defer mockServer.Close()

		mockURL := mockServer.URL + "/beats/latest/8.8.3-SNAPSHOT.json"
		artifactsSnapshot := newArtifactsSnapshotCustom(mockURL)
		version, err := artifactsSnapshot.GetSnapshotArtifactVersion("beats", "8.8.3-SNAPSHOT")
		assert.ErrorContains(t, err, "could not parse the build_id")
		assert.ErrorContains(t, err, "bd8691a")
		assert.Empty(t, version)
	})
}

type MockHandler struct {
	Responses map[string]string
}

func (m *MockHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path

	response, ok := m.Responses[path]
	if !ok {
		http.NotFound(w, r)
		return
	}

	fmt.Fprint(w, response)
}

func TestArtifactsSnapshotResolver(t *testing.T) {

	t.Run("Positive: parses commit has and returns full version", func(t *testing.T) {

		artifactsSnapshotMockManifest, err := os.ReadFile(filepath.Join(".", "_testresources", "dra", "snapshot_artifacts_test.json"))
		require.NoError(t, err, "couldn't read _testresources/dra/snapshot_artifacts_test.json")
		mockResponses := map[string]string{
			"/beats/latest/8.9.0-SNAPSHOT.json": `{
				"version" : "8.9.0-SNAPSHOT",
				"build_id" : "8.9.0-b6405422",
				"manifest_url" : "https://artifacts-snapshot.elastic.co/beats/8.9.0-b6405422/manifest-8.9.0-SNAPSHOT.json",
				"summary_url" : "https://artifacts-snapshot.elastic.co/beats/8.9.0-b6405422/summary-8.9.0-SNAPSHOT.html"
			}`,
			"/beats/8.9.0-b6405422/manifest-8.9.0-SNAPSHOT.json": string(artifactsSnapshotMockManifest),
		}

		mockHandler := &MockHandler{
			Responses: mockResponses,
		}

		server := httptest.NewServer(mockHandler)
		defer server.Close()

		urlResolver := newCustomSnapshotURLResolver("auditbeat-8.9.0-SNAPSHOT-amd64.deb", "auditbeat", "beats", "8.9.0-SNAPSHOT", server.URL)
		url, shaUrl, err := urlResolver.Resolve()
		assert.Equal(t, "https://artifacts-snapshot.elastic.co/auditbeat-8.9.0-SNAPSHOT-amd64.deb", url)
		assert.Equal(t, "https://artifacts-snapshot.elastic.co/auditbeat-8.9.0-SNAPSHOT-amd64.deb.sha512", shaUrl)
		assert.NoError(t, err, "Expected no error")
	})
}
