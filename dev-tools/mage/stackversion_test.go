// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package mage

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStackReleaseUnmarshal(t *testing.T) {
	t.Run("all fields populated", func(t *testing.T) {
		jsonData := `{
			"version": "9.2.4",
			"public_release_date": "2026-01-13",
			"is_end_of_support": false,
			"end_of_support_date": "2028-10-07",
			"is_end_of_maintenance": false,
			"end_of_maintenance_date": "2028-04-10",
			"is_retired": false,
			"retired_date": null,
			"manifest": "https://artifacts.elastic.co/downloads/9.2.4.json"
		}`

		var release StackRelease
		err := json.Unmarshal([]byte(jsonData), &release)
		require.NoError(t, err)

		assert.Equal(t, "9.2.4", release.Version)
		assert.Equal(t, "2026-01-13", release.PublicReleaseDate)
		assert.False(t, release.IsEndOfSupport)
		require.NotNil(t, release.EndOfSupportDate)
		assert.Equal(t, "2028-10-07", *release.EndOfSupportDate)
		assert.False(t, release.IsEndOfMaintenance)
		require.NotNil(t, release.EndOfMaintenanceDate)
		assert.Equal(t, "2028-04-10", *release.EndOfMaintenanceDate)
		assert.False(t, release.IsRetired)
		assert.Nil(t, release.RetiredDate)
		require.NotNil(t, release.Manifest)
		assert.Equal(t, "https://artifacts.elastic.co/downloads/9.2.4.json", *release.Manifest)
	})

	t.Run("releases array", func(t *testing.T) {
		jsonData := `{
			"releases": [
				{"version": "9.2.4", "public_release_date": "2026-01-13", "is_end_of_support": false, "end_of_support_date": null, "is_end_of_maintenance": false, "end_of_maintenance_date": null, "is_retired": false, "retired_date": null, "manifest": null},
				{"version": "9.2.3", "public_release_date": "2025-12-01", "is_end_of_support": false, "end_of_support_date": null, "is_end_of_maintenance": false, "end_of_maintenance_date": null, "is_retired": false, "retired_date": null, "manifest": null}
			]
		}`

		var response StackReleasesResponse
		err := json.Unmarshal([]byte(jsonData), &response)
		require.NoError(t, err)

		assert.Len(t, response.Releases, 2)
		assert.Equal(t, "9.2.4", response.Releases[0].Version)
		assert.Equal(t, "9.2.3", response.Releases[1].Version)
	})
}

func TestLatestPatchForMinors(t *testing.T) {
	t.Run("multiple minors", func(t *testing.T) {
		response := &StackReleasesResponse{
			Releases: []StackRelease{
				{Version: "9.2.4", PublicReleaseDate: "2026-01-13"},
				{Version: "9.2.3", PublicReleaseDate: "2025-12-01"},
				{Version: "9.2.0", PublicReleaseDate: "2025-10-01"},
				{Version: "9.1.5", PublicReleaseDate: "2025-11-15"},
				{Version: "9.1.0", PublicReleaseDate: "2025-08-01"},
				{Version: "8.17.2", PublicReleaseDate: "2025-09-01"},
				{Version: "8.17.0", PublicReleaseDate: "2025-07-01"},
				{Version: "8.16.3", PublicReleaseDate: "2025-06-01"},
			},
		}

		latestPatches, err := response.LatestPatchForMinors()
		require.NoError(t, err)

		assert.Len(t, latestPatches, 4)
		assert.Equal(t, "9.2.4", latestPatches["9.2"].Version)
		assert.Equal(t, "9.1.5", latestPatches["9.1"].Version)
		assert.Equal(t, "8.17.2", latestPatches["8.17"].Version)
		assert.Equal(t, "8.16.3", latestPatches["8.16"].Version)
	})

	t.Run("unordered input", func(t *testing.T) {
		response := &StackReleasesResponse{
			Releases: []StackRelease{
				{Version: "9.2.0", PublicReleaseDate: "2025-10-01"},
				{Version: "9.2.4", PublicReleaseDate: "2026-01-13"},
				{Version: "9.2.2", PublicReleaseDate: "2025-11-15"},
				{Version: "9.2.3", PublicReleaseDate: "2025-12-01"},
				{Version: "9.2.1", PublicReleaseDate: "2025-10-15"},
			},
		}

		latestPatches, err := response.LatestPatchForMinors()
		require.NoError(t, err)

		assert.Len(t, latestPatches, 1)
		assert.Equal(t, "9.2.4", latestPatches["9.2"].Version)
	})

	t.Run("skips invalid versions", func(t *testing.T) {
		response := &StackReleasesResponse{
			Releases: []StackRelease{
				{Version: "9.2.4", PublicReleaseDate: "2026-01-13"},
				{Version: "invalid", PublicReleaseDate: "2025-01-01"},
				{Version: "9.1.0", PublicReleaseDate: "2025-08-01"},
			},
		}

		latestPatches, err := response.LatestPatchForMinors()
		require.NoError(t, err)

		assert.Len(t, latestPatches, 2)
		assert.Equal(t, "9.2.4", latestPatches["9.2"].Version)
		assert.Equal(t, "9.1.0", latestPatches["9.1"].Version)
	})

	t.Run("empty releases", func(t *testing.T) {
		response := &StackReleasesResponse{
			Releases: []StackRelease{},
		}

		latestPatches, err := response.LatestPatchForMinors()
		require.NoError(t, err)

		assert.Empty(t, latestPatches)
	})
}

func TestGetLatestPatchForMinor(t *testing.T) {
	response := &StackReleasesResponse{
		Releases: []StackRelease{
			{Version: "9.2.4", PublicReleaseDate: "2026-01-13"},
			{Version: "9.2.3", PublicReleaseDate: "2025-12-01"},
			{Version: "9.1.5", PublicReleaseDate: "2025-11-15"},
		},
	}

	t.Run("found", func(t *testing.T) {
		release := response.GetLatestPatchForMinor("9.2")
		require.NotNil(t, release)
		assert.Equal(t, "9.2.4", release.Version)

		release = response.GetLatestPatchForMinor("9.1")
		require.NotNil(t, release)
		assert.Equal(t, "9.1.5", release.Version)
	})

	t.Run("not found", func(t *testing.T) {
		release := response.GetLatestPatchForMinor("8.0")
		assert.Nil(t, release)
	})
}

func TestFetchStackReleases(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodGet, r.Method)

			response := StackReleasesResponse{
				Releases: []StackRelease{
					{Version: "9.2.4", PublicReleaseDate: "2026-01-13"},
					{Version: "9.2.3", PublicReleaseDate: "2025-12-01"},
				},
			}

			w.Header().Set("Content-Type", "application/json")
			err := json.NewEncoder(w).Encode(response)
			assert.NoError(t, err)
		}))
		defer server.Close()

		resp, err := fetchStackReleases(context.Background(), server.URL)
		require.NoError(t, err)
		require.NotNil(t, resp)

		assert.Len(t, resp.Releases, 2)
		assert.Equal(t, "9.2.4", resp.Releases[0].Version)
	})

	t.Run("http error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer server.Close()

		resp, err := fetchStackReleases(context.Background(), server.URL)
		assert.Error(t, err)
		assert.Nil(t, resp)
		assert.Contains(t, err.Error(), "500")
	})

	t.Run("invalid json", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, err := w.Write([]byte("not valid json"))
			assert.NoError(t, err)
		}))
		defer server.Close()

		resp, err := fetchStackReleases(context.Background(), server.URL)
		assert.Error(t, err)
		assert.Nil(t, resp)
		assert.Contains(t, err.Error(), "parsing response")
	})
}
