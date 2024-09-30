// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package product_versions

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/elastic/elastic-agent/pkg/version"
)

const (
	// Every product on the version list has a unique product ID
	// This product ID belongs to Elastic Agent excluding alpha/beta/RC versions.
	elasticAgentProductID = "bltce270507523f4c56"
	productVersionsAPIURL = "https://www.elastic.co/api"
)

type item struct {
	// Version contains the actual semantic version, e.g. `8.12.1`
	Version string `json:"version_number"`
	// Product contains a list of product IDs.
	// For the agent it should  be a single item that equals `elasticAgentProductID`
	Product []string `json:"product"`
}

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

type ProductVersionsClientOpt func(pvc *ProductVersionsClient)

func WithUrl(url string) ProductVersionsClientOpt {
	return func(pvc *ProductVersionsClient) { pvc.url = url }
}

func WithHttpClient(client httpDoer) ProductVersionsClientOpt {
	return func(pvc *ProductVersionsClient) { pvc.c = client }
}

type ProductVersionsClient struct {
	c   httpDoer
	url string
}

// NewProductVersionsClient creates a new client applying all the given options.
// If not set by the options, the new client will use the default HTTP client and
// the default URL from `productVersionsAPIURL`.
//
// All the timeout/retry/backoff behavior must be implemented by the `httpDoer` interface
// and set by the `WithClient` option.
func NewProductVersionsClient(opts ...ProductVersionsClientOpt) *ProductVersionsClient {
	c := &ProductVersionsClient{
		url: productVersionsAPIURL,
		c:   http.DefaultClient,
	}

	for _, opt := range opts {
		opt(c)
	}

	return c
}

// FetchAgentVersions returns a sortable list of parsed semantic versions for Elastic Agent.
// This list contains only publicly available versions/releases ordered by their creation date.
func (pvc *ProductVersionsClient) FetchAgentVersions(ctx context.Context) (version.SortableParsedVersions, error) {
	url := pvc.url + "/product_versions"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		err = fmt.Errorf("failed to create request: %w", err)
		return nil, err
	}

	resp, err := pvc.c.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to do request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	// The body is large (> 15MB), so the streaming decoder is used
	d := json.NewDecoder(resp.Body)

	// there are 2 list levels in the response
	var versions [][]item
	err = d.Decode(&versions)
	if err != nil {
		return nil, fmt.Errorf("failed to decode JSON: %w", err)
	}
	if len(versions) == 0 {
		return []*version.ParsedSemVer{}, nil
	}

	var versionList version.SortableParsedVersions
	for _, i := range versions {
		for _, v := range i {
			if len(v.Product) != 1 {
				continue
			}
			if v.Product[0] != elasticAgentProductID {
				continue
			}
			parsed, err := version.ParseVersion(v.Version)
			if err != nil {
				return nil, fmt.Errorf("failed to parse %s: %w", v.Version, err)
			}
			versionList = append(versionList, parsed)
		}
	}

	return versionList, nil
}
