// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package download

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/cenkalti/backoff/v7"

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

	opNotify := func(err error, retryAfter time.Duration) {
		btr.logger.Warnf("request failed: %s, retrying in %s", err, retryAfter)
	}

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
	opFunc := func() (*http.Response, error) {
		if resettableBody != nil {
			if _, err := resettableBody.Seek(0, io.SeekStart); err != nil {
				btr.logger.Errorf("error while resetting request body: %v", err)
			}
		}

		attempt++
		resp, err := btr.next.RoundTrip(req)
		if err != nil {
			btr.logger.Errorf("attempt %d: error round-trip: %v", attempt, err)
			return nil, err
		}

		if resp.StatusCode >= 400 {
			if err := resp.Body.Close(); err != nil {
				btr.logger.Errorf("attempt %d: error closing the response body: %v", attempt, err)
			}
			btr.logger.Errorf("attempt %d: received response status: %d", attempt, resp.StatusCode)
			return nil, errors.New(fmt.Sprintf("received response status: %d", resp.StatusCode))
		}

		return resp, nil
	}

	resp, err := backoff.Retry(req.Context(), opFunc, backoff.WithBackOff(exp), backoff.WithNotify(opNotify))
	if err != nil {
		if re := backoff.AsRetryError(err); re != nil && re.LastErr != nil {
			return nil, re.LastErr
		}
		return nil, err
	}
	return resp, nil
}
