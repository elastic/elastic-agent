// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package otel

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"syscall"
	"time"

	"github.com/cenkalti/backoff/v4"

	"github.com/elastic/elastic-agent/internal/pkg/otel/extension/elasticdiagnostics"
)

// actionDialRetryInitialInterval, actionDialRetryMaxInterval, and
// actionDialRetryMaxTime bound the backoff used to retry connecting to the
// elasticdiagnostics extension when the collector is mid-restart (e.g. after
// a config change touching otel components). Only connection-establishment
// failures are retried, see IsCollectorUnavailable.
//
// actionDialRetryMaxTime caps the retry loop independent of the caller's ctx,
// which may carry a much longer deadline (up to an hour, derived from a
// Fleet action's own declared timeout): if the collector hasn't come back
// within this window, something is more seriously wrong than a brief
// restart, and it also keeps a caller that forgets to bound ctx (e.g.
// context.Background()) from retrying forever. Vars, not consts, so tests
// can shrink them.
var (
	actionDialRetryInitialInterval = 200 * time.Millisecond
	actionDialRetryMaxInterval     = 2 * time.Second
	actionDialRetryMaxTime         = 30 * time.Second
)

// onDialRetry, set only in tests, is called immediately after a retryable
// dial failure, before backing off. It lets tests synchronize deterministically
// with a retry actually happening instead of relying on a sleep.
var onDialRetry func()

// PerformActionExt routes a Fleet action to a receiver mapped to componentID.
// It connects to the elasticdiagnostics extension over its Unix socket, the
// same transport used by PerformDiagnosticsExt, and returns the result map
// produced by the receiver's registered action handler.
//
// If the collector is mid-restart, the connection attempt is retried with a bounded
// backoff until ctx is done. Once a request has actually been sent, failures
// are returned immediately without retrying: re-sending risks the receiver
// having already started executing a non-idempotent action (e.g. an osquery
// live query), so only the "couldn't connect at all" case is safe to retry.
func PerformActionExt(ctx context.Context, componentID string, name string, params map[string]any) (map[string]any, error) {
	httpClient := newExtensionHTTPClient()

	body, err := json.Marshal(elasticdiagnostics.ActionRequest{
		ComponentID: componentID,
		Name:        name,
		Params:      params,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal action request: %w", err)
	}

	// backoff.WithContext makes NextBackOff() stop as soon as ctx is done, on
	// top of ExponentialBackOff's own MaxElapsedTime -- whichever comes first
	// -- with no extra goroutine needed to bridge ctx into the backoff.
	expBo := backoff.NewExponentialBackOff(
		backoff.WithInitialInterval(actionDialRetryInitialInterval),
		backoff.WithMaxInterval(actionDialRetryMaxInterval),
		backoff.WithMaxElapsedTime(actionDialRetryMaxTime),
	)
	boCtx := backoff.WithContext(expBo, ctx)

	resp, err := backoff.RetryNotifyWithData(
		func() (*http.Response, error) {
			// The request itself uses ctx, not the retry max time: once connected, a
			// legitimately long-running action must not be cut short by it.
			req, reqErr := http.NewRequestWithContext(ctx, http.MethodPost, "http://localhost/actions", bytes.NewReader(body))
			if reqErr != nil {
				return nil, backoff.Permanent(fmt.Errorf("failed to create request: %w", reqErr))
			}
			resp, doErr := httpClient.Do(req)
			if doErr == nil {
				return resp, nil
			}
			if !IsCollectorUnavailable(doErr) {
				return nil, backoff.Permanent(fmt.Errorf("failed to perform request: %w", doErr))
			}
			return nil, fmt.Errorf("failed to perform request: %w", doErr)
		},
		boCtx,
		func(error, time.Duration) {
			if onDialRetry != nil {
				onDialRetry()
			}
		},
	)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	var actionResp elasticdiagnostics.ActionResponse
	if err := json.Unmarshal(respBytes, &actionResp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		if actionResp.Error != "" {
			return nil, errors.New(actionResp.Error)
		}
		return nil, fmt.Errorf("unexpected status code performing action: %d", resp.StatusCode)
	}

	if actionResp.Error != "" {
		return actionResp.Result, errors.New(actionResp.Error)
	}

	return actionResp.Result, nil
}

// IsCollectorUnavailable reports whether err indicates the elasticdiagnostics
// extension's socket isn't accepting connections: the socket file is
// missing, or nothing is listening on it. Both can only occur while
// establishing a connection, never after a request has been sent, which is
// what makes this safe to use as a retry condition in PerformActionExt
// without risking a duplicate action execution.
//
// This is also the classification PerformComponentDiagnostics uses to detect
// that the collector isn't running, so both share it rather than each
// re-implementing the same errors.Is chain.
func IsCollectorUnavailable(err error) bool {
	return errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ECONNREFUSED)
}
