// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package manifest

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDownloadFile(t *testing.T) {
	const content = "some content"
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(content))
	}))
	t.Cleanup(s.Close)

	target := filepath.Join(t.TempDir(), "some-file.txt")
	name, err := downloadFile(t.Context(), s.URL, target)
	require.NoError(t, err)
	assert.Equal(t, target, name)
	got, err := os.ReadFile(target)
	require.NoError(t, err)
	assert.Equal(t, content, string(got))
}

func TestDownloadFileBadStatus(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "temporarily unavailable", http.StatusServiceUnavailable)
	}))
	t.Cleanup(s.Close)

	target := filepath.Join(t.TempDir(), "some-file.txt")
	_, err := downloadFile(t.Context(), s.URL, target)
	require.Error(t, err, "a bad HTTP status must be an error so the caller retries")

	got, readErr := os.ReadFile(target)
	if readErr == nil {
		assert.Empty(t, string(got), "the error response body must not be saved as the file")
	}
}

func TestDownloadManifestDataBadStatus(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "temporarily unavailable", http.StatusServiceUnavailable)
	}))
	t.Cleanup(s.Close)

	_, err := downloadManifestData(t.Context(), s.URL)
	require.Error(t, err, "a bad HTTP status must be an error so the caller retries")
}
