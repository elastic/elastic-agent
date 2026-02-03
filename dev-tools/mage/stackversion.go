// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package mage

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/elastic/elastic-agent/pkg/version"
)

const stackReleasesURL = "https://ela.st/past-stack-releases"

// StackRelease represents a single release entry from the stack releases API.
type StackRelease struct {
	Version              string  `json:"version"`
	PublicReleaseDate    string  `json:"public_release_date"`
	IsEndOfSupport       bool    `json:"is_end_of_support"`
	EndOfSupportDate     *string `json:"end_of_support_date"`
	IsEndOfMaintenance   bool    `json:"is_end_of_maintenance"`
	EndOfMaintenanceDate *string `json:"end_of_maintenance_date"`
	IsRetired            bool    `json:"is_retired"`
	RetiredDate          *string `json:"retired_date"`
	Manifest             *string `json:"manifest"`
}

// StackReleasesResponse represents the response from the stack releases API.
type StackReleasesResponse struct {
	Releases []StackRelease `json:"releases"`
}

// FetchStackReleases fetches release information from the Elastic stack releases API.
func FetchStackReleases(ctx context.Context) (*StackReleasesResponse, error) {
	return fetchStackReleases(ctx, stackReleasesURL)
}

func fetchStackReleases(ctx context.Context, url string) (*StackReleasesResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching stack releases: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d %s", resp.StatusCode, http.StatusText(resp.StatusCode))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}

	var response StackReleasesResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, fmt.Errorf("parsing response: %w", err)
	}

	return &response, nil
}

// LatestPatchForMinors returns a map from "major.minor" version strings to the
// latest patch release for that minor version.
func (r *StackReleasesResponse) LatestPatchForMinors() (map[string]StackRelease, error) {
	result := make(map[string]StackRelease)
	parsedVersions := make(map[string]*version.ParsedSemVer)

	for _, release := range r.Releases {
		parsed, err := version.ParseVersion(release.Version)
		if err != nil {
			// Skip releases that don't parse as valid semver
			continue
		}

		minorKey := fmt.Sprintf("%d.%d", parsed.Major(), parsed.Minor())

		existing, exists := parsedVersions[minorKey]
		if !exists || existing.Less(*parsed) {
			result[minorKey] = release
			parsedVersions[minorKey] = parsed
		}
	}

	return result, nil
}

// GetLatestPatchForMinor returns the latest patch release for a specific minor version.
// The minorVersion parameter should be in "major.minor" format (e.g., "9.2").
// Returns nil if no releases are found for that minor version.
func (r *StackReleasesResponse) GetLatestPatchForMinor(minorVersion string) *StackRelease {
	latestPatches, err := r.LatestPatchForMinors()
	if err != nil {
		return nil
	}

	release, exists := latestPatches[minorVersion]
	if !exists {
		return nil
	}

	return &release
}
