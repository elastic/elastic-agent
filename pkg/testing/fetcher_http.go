// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package testing

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
)

const defaultAgentBaseURL = "https://artifacts.elastic.co/downloads/beats/elastic-agent/"

type HttpFetcher struct {
	baseURL string
}

type HttpFetcherOpt func(hf *HttpFetcher)

func WithBaseURL(baseURL string) HttpFetcherOpt {
	return func(hf *HttpFetcher) {
		hf.baseURL = baseURL
	}
}

func NewHttpFetcher(opts ...HttpFetcherOpt) *HttpFetcher {

	f := &HttpFetcher{
		baseURL: defaultAgentBaseURL,
	}

	for _, o := range opts {
		o(f)
	}

	return f
}

func (h HttpFetcher) Name() string {
	return fmt.Sprintf("httpFetcher-%s", sanitizeName(h.baseURL))
}

func (h HttpFetcher) Fetch(ctx context.Context, operatingSystem string, architecture string, version string) (FetcherResult, error) {
	suffix, err := GetPackageSuffix(operatingSystem, architecture)
	if err != nil {
		return nil, err
	}
	// https://artifacts.elastic.co/downloads/beats/elastic-agent/elastic-agent-8.12.1-linux-arm64.tar.gz
	packageName := fmt.Sprintf("elastic-agent-%s-%s", version, suffix)
	return &httpFetcherResult{
		packageName: packageName,
		baseURL:     h.baseURL,
	}, nil

}

type httpFetcherResult struct {
	baseURL     string
	packageName string
}

func (h httpFetcherResult) Name() string {
	return h.packageName
}

func (h httpFetcherResult) Fetch(ctx context.Context, l Logger, dir string) error {
	var err error
	baseURL := h.baseURL
	if !strings.HasSuffix(baseURL, "/") {
		baseURL += "/"
	}
	packageURL := baseURL + h.packageName
	packageSHAURL := baseURL + h.packageName + extHash
	packageASCURL := baseURL + h.packageName + extAsc
	err = DownloadPackage(ctx, l, http.DefaultClient, packageURL, filepath.Join(dir, h.packageName))
	err = errors.Join(err, DownloadPackage(ctx, l, http.DefaultClient, packageSHAURL, filepath.Join(dir, h.packageName+extHash)))
	err = errors.Join(err, DownloadPackage(ctx, l, http.DefaultClient, packageASCURL, filepath.Join(dir, h.packageName+extAsc)))
	return err
}

func sanitizeName(name string) string {
	sanitized := strings.ReplaceAll(name, ":", "-")
	sanitized = strings.ReplaceAll(name, "/", "-")
	return sanitized
}
