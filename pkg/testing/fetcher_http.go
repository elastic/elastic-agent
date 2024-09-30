// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package testing

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"regexp"
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
	return fmt.Sprintf("httpFetcher-%s", sanitizeFetcherName(h.baseURL))
}

func (h HttpFetcher) Fetch(ctx context.Context, operatingSystem string, architecture string, version string, packageFormat string) (FetcherResult, error) {
	suffix, err := GetPackageSuffix(operatingSystem, architecture, packageFormat)
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

var hostRegexString = `^http(?:s?)://([a-z,A-z,0-9,\.]+)(?::[0-9]+)?(?:/.*)*$`
var hostRegex = regexp.MustCompile(hostRegexString)

const hostRegexGroup = 1

func sanitizeFetcherName(name string) string {
	match := hostRegex.FindStringSubmatch(name)
	if len(match) > 1 {
		host := match[hostRegexGroup]
		return host
	}
	// falllback in case we don't match the url regex
	sanitized := strings.ReplaceAll(name, ":", "-")
	sanitized = strings.ReplaceAll(sanitized, "/", "-")
	return sanitized
}
