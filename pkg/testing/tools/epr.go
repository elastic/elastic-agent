// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

const eprProd = "https://epr.elastic.co"

// / PackageSearchResult contains basic info on a package returned by a search
type PackageSearchResult struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Release string `json:"release"`
	Path    string `json:"path"`
}

// GetLatestPackageRelease returns the version string of the latest package release
func GetLatestPackageRelease(ctx context.Context, packageName string) (string, error) {
	endpoint := fmt.Sprintf("%s/search?package=%s&all=false", eprProd, packageName)
	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return "", fmt.Errorf("error creating HTTP request: %w", err)
	}
	resp, err := http.DefaultClient.Do(req) //nolint:gosec,nolintlint // it's a test
	//create body before we check for errors, easier to format error strings that way
	body, errRead := io.ReadAll(resp.Body)
	if errRead != nil {
		return "", fmt.Errorf("error reading body of HTTP resp: %w", err)
	}
	resp.Body.Close()
	if err != nil {
		return "", fmt.Errorf("failed to create search request for EPR (%s): %w", body, err)
	}
	if resp.StatusCode >= 300 {
		return "", fmt.Errorf("bad status code in response from EPR: %d - %s", resp.StatusCode, resp.Status)
	}

	parsedResp := []PackageSearchResult{}
	err = json.Unmarshal(body, &parsedResp)
	if err != nil {
		return "", fmt.Errorf("error parsing search response: %w", err)
	}
	// if we set &all=false, we'll get at most one result
	if len(parsedResp) < 1 {
		return "", fmt.Errorf("no packages matching '%s' found", packageName)
	}

	return parsedResp[0].Version, nil
}
