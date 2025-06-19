// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package ess

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/elastic/elastic-agent/pkg/testing/common"
)

type Client struct {
	config *Config
	client *http.Client
	logger common.Logger
}

func NewClient(config Config) *Client {
	cfg := defaultConfig()
	cfg.Merge(config)

	c := new(Client)
	c.client = http.DefaultClient
	c.config = cfg

	return c
}

func (c *Client) SetLogger(logger common.Logger) {
	c.logger = logger
}

func (c *Client) doGet(ctx context.Context, relativeUrl string) (*http.Response, error) {
	// We don't use url.JoinPath because it escapes the "?" in
	// relativeUrl if it contains a query string
	u := c.config.BaseUrl + "/" + relativeUrl

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, fmt.Errorf("unable to create GET request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("ApiKey %s", c.config.ApiKey))

	return c.client.Do(req)
}

func (c *Client) doPost(ctx context.Context, relativeUrl, contentType string, body io.Reader) (*http.Response, error) {
	return c.doWrite(ctx, http.MethodPost, relativeUrl, contentType, body)
}

func (c *Client) doPut(ctx context.Context, relativeUrl, contentType string, body io.Reader) (*http.Response, error) {
	return c.doWrite(ctx, http.MethodPut, relativeUrl, contentType, body)
}

func (c *Client) doWrite(ctx context.Context, method, relativeUrl, contentType string, body io.Reader) (*http.Response, error) {
	u, err := url.JoinPath(c.config.BaseUrl, relativeUrl)
	if err != nil {
		return nil, fmt.Errorf("unable to create API URL: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return nil, fmt.Errorf("unable to create POST request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("ApiKey %s", c.config.ApiKey))
	req.Header.Set("Content-Type", contentType)

	return c.client.Do(req)
}

func (c *Client) BaseURL() string {
	return c.config.BaseUrl
}
