// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package http

import (
	"fmt"
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
	// opFunc is a wrapper used by the backoff function. Backoff will keep trying
	// to send a request until the request succeeds or the context expires.
	//
	// When the request encounters an error, opFunc returns an error to trigger a
	// retry.
	//
	// When the request succeeds, opFunc returns nil and the response is sent up the call stack
	//
	// The response body is closed for failed requests (status >= 400). It is the
	// callers responsibility to close the response body for successful requests
	opFunc := func() error {
		resp, err = btr.next.RoundTrip(req) //nolint:bodyclose
		if err != nil {
			return err
		}

		if resp.StatusCode >= 400 {
			if err := resp.Body.Close(); err != nil {
				btr.logger.Errorf("error closing the response body: %w", err)
			}
			return errors.New(fmt.Sprintf("received response status: %d", resp.StatusCode))
		}

		return nil
	}

	return resp, backoff.RetryNotify(opFunc, boCtx, opNotify)
}
