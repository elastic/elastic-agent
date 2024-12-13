// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package http

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/cenkalti/backoff/v4"

	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

func WithBackoff(rtt http.RoundTripper, logger *logger.Logger) http.RoundTripper {
	if rtt == nil {
		rtt = http.DefaultTransport
	}

	return &BackoffRoundTripper{next: rtt, logger: logger}
}

type BackoffRoundTripper struct {
	next   http.RoundTripper
	logger *logger.Logger
}

func (btr *BackoffRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	exp := backoff.NewExponentialBackOff()
	boCtx := backoff.WithContext(exp, req.Context())

	opNotify := func(err error, retryAfter time.Duration) {
		btr.logger.Warnf("request failed: %s, retrying in %s", err, retryAfter)
	}

	var resp *http.Response
	var err error
	var resettableBody *bytes.Reader

	if req.Body != nil {
		data, err := io.ReadAll(req.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read request body: %w", err)
		}
		req.Body.Close()

		resettableBody = bytes.NewReader(data)
		req.Body = io.NopCloser(resettableBody)
	}
	// opFunc implements the retry logic for the backoff mechanism.
	//
	// - For each attempt, the request body is reset (if non-nil) to allow reuse.
	// - Requests with errors or responses with status >= 400 trigger retries.
	// - The response body is closed for failed requests to free resources.
	// - A successful request (status < 400) stops the retries and returns the response.
	attempt := 1
	opFunc := func() error {
		if resettableBody != nil {
			resettableBody.Seek(0, io.SeekStart)
		}

		attempt++
		resp, err = btr.next.RoundTrip(req) //nolint:bodyclose
		if err != nil {
			btr.logger.Errorf("attempt %d: error round-trip: %w", err)
			return err
		}

		if resp.StatusCode >= 400 {
			if err := resp.Body.Close(); err != nil {
				btr.logger.Errorf("attempt %d: error closing the response body: %w", attempt, err)
			}
			btr.logger.Errorf("attempt %d: received response status: %d", attempt, resp.StatusCode)
			return errors.New(fmt.Sprintf("received response status: %d", resp.StatusCode))
		}

		return nil
	}

	return resp, backoff.RetryNotify(opFunc, boCtx, opNotify)
}
