// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package client

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/internal/pkg/release"
	"github.com/elastic/elastic-agent/internal/pkg/remote"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

const (
	apiStatusTimeout = 15 * time.Second
	statusPath       = "/api/status"
)

// Sender is an sender interface describing client behavior.
type Sender interface {
	Send(
		ctx context.Context,
		method string,
		path string,
		params url.Values,
		headers http.Header,
		body io.Reader,
	) (*http.Response, error)

	URI() string
}

// Default value for Elastic-Api-Version header when sending requests to Fleet (that's the only version we have at the time of writing)
const defaultFleetApiVersion = "2023-06-01"

var baseRoundTrippers = func(rt http.RoundTripper) (http.RoundTripper, error) {
	rt = NewFleetUserAgentRoundTripper(rt, release.Version())

	rt = NewElasticApiVersionRoundTripper(rt, defaultFleetApiVersion)

	return rt, nil
}

func init() {
	val, ok := os.LookupEnv("DEBUG_AGENT")
	if ok && val == "1" {
		fn := baseRoundTrippers
		baseRoundTrippers = func(rt http.RoundTripper) (http.RoundTripper, error) {
			rt, err := fn(rt)
			if err != nil {
				return nil, err
			}

			l, err := logger.New("fleet_client", false)
			if err != nil {
				return nil, errors.New(err, "could not create the logger for debugging HTTP request")
			}

			return remote.NewDebugRoundTripper(rt, l), nil
		}
	}
}

// NewAuthWithConfig returns a fleet-server client that will:
//
// - Send the API Key on every HTTP request.
// - Ensure a minimun version of fleet-server is required.
// - Send the Fleet User Agent on every HTTP request.
func NewAuthWithConfig(log *logger.Logger, apiKey string, cfg remote.Config) (*remote.Client, error) {
	return remote.NewWithConfig(log, cfg, func(rt http.RoundTripper) (http.RoundTripper, error) {
		rt, err := baseRoundTrippers(rt)
		if err != nil {
			return nil, err
		}

		rt, err = NewFleetAuthRoundTripper(rt, apiKey)
		if err != nil {
			return nil, err
		}

		return rt, nil
	})
}

// NewWithConfig takes a fleet-server configuration and create a remote.client with the appropriate tripper.
func NewWithConfig(log *logger.Logger, cfg remote.Config) (*remote.Client, error) {
	return remote.NewWithConfig(log, cfg, baseRoundTrippers)
}

// ExtractError extracts error from a fleet-server response
func ExtractError(resp io.Reader) error {
	// Let's try to extract a high level fleet-server error.
	e := &struct {
		StatusCode int    `json:"statusCode"`
		Error      string `json:"error"`
		Message    string `json:"message"`
	}{}

	data, err := io.ReadAll(resp)
	if err != nil {
		return errors.New(err, "fail to read original error")
	}

	err = json.Unmarshal(data, e)
	if err == nil {
		// System errors doesn't return a message, fleet code can return a Message key which has more
		// information.
		if len(e.Message) == 0 {
			return fmt.Errorf("status code: %d, fleet-server returned an error: %s", e.StatusCode, e.Error)
		}
		return fmt.Errorf(
			"status code: %d, fleet-server returned an error: %s, message: %s",
			e.StatusCode,
			e.Error,
			e.Message,
		)
	}

	return fmt.Errorf("could not decode the response, raw response: %s", string(data))
}

func CheckRemote(ctx context.Context, c Sender) error {
	ctx, cancel := context.WithTimeout(ctx, apiStatusTimeout)
	defer cancel()

	resp, err := c.Send(ctx, http.MethodGet, statusPath, nil, nil, nil)
	if err != nil {
		return fmt.Errorf("fail to communicate with Fleet Server API client hosts: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("fleet server ping returned a bad status code: %d", resp.StatusCode)
	}

	// discard body for proper cancellation and connection reuse
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	return nil
}
