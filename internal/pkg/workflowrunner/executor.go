// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package workflowrunner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// defaultMaxBodyBytes caps how much of a response body is stored in the result document.
const defaultMaxBodyBytes = 1 << 20

// responseHeadersDropped are never copied into the result document.
var responseHeadersDropped = map[string]struct{}{
	"Set-Cookie": {},
}

// Result is the outcome of one HTTP call.
type Result struct {
	StatusCode int
	Headers    map[string]string
	Body       string
	BodyBytes  int64
	Truncated  bool
	Start      time.Time
	End        time.Time
	Error      string
}

// Call is one validated HTTP request.
type Call struct {
	Method  string
	Target  *url.URL
	Headers map[string]string
	Body    []byte
	// MaxRedirects is how many redirects to follow before returning the redirect response.
	MaxRedirects int
	// MaxResponseBytes lowers the executor's body cap when positive.
	MaxResponseBytes int64
}

// Executor performs workflow HTTP calls from the host network.
type Executor struct {
	transport    http.RoundTripper
	maxBodyBytes int64
}

// NewExecutor returns an Executor that resolves names with the host resolver
// and honors HTTP(S)_PROXY / NO_PROXY.
func NewExecutor() *Executor {
	return &Executor{
		transport:    http.DefaultTransport.(*http.Transport).Clone(),
		maxBodyBytes: defaultMaxBodyBytes,
	}
}

// Do performs the request. Transport failures are reported in Result.Error, not
// as an error, so the caller always has a result to store.
func (e *Executor) Do(ctx context.Context, call Call) Result {
	res := Result{Start: time.Now().UTC()}

	var body io.Reader
	if len(call.Body) > 0 {
		body = bytes.NewReader(call.Body)
	}
	httpReq, err := http.NewRequestWithContext(ctx, call.Method, call.Target.String(), body)
	if err != nil {
		res.Error = "building request: " + err.Error()
		res.End = time.Now().UTC()
		return res
	}
	for k, v := range call.Headers {
		if strings.EqualFold(k, "Host") {
			httpReq.Host = v
			continue
		}
		httpReq.Header.Set(k, v)
	}

	// net/http drops Authorization and Cookie when a redirect leaves the original host.
	client := &http.Client{
		Transport: e.transport,
		CheckRedirect: func(next *http.Request, via []*http.Request) error {
			if len(via) > call.MaxRedirects {
				return http.ErrUseLastResponse
			}
			if next.URL.Scheme != "http" && next.URL.Scheme != "https" {
				return fmt.Errorf("redirect to unsupported URL scheme %q", next.URL.Scheme)
			}
			return nil
		},
	}

	resp, err := client.Do(httpReq)
	if err != nil {
		res.Error = describeTransportError(err)
		res.End = time.Now().UTC()
		return res
	}
	defer resp.Body.Close()

	res.StatusCode = resp.StatusCode
	res.Headers = make(map[string]string, len(resp.Header))
	for k, v := range resp.Header {
		if _, drop := responseHeadersDropped[k]; drop {
			continue
		}
		res.Headers[k] = strings.Join(v, ", ")
	}

	limit := e.maxBodyBytes
	if call.MaxResponseBytes > 0 && call.MaxResponseBytes < limit {
		limit = call.MaxResponseBytes
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if int64(len(data)) > limit {
		data = data[:limit]
		res.Truncated = true
	}
	res.Body = string(data)
	res.BodyBytes = int64(len(data))
	if err != nil {
		res.Error = "reading response body: " + describeTransportError(err)
	}
	res.End = time.Now().UTC()
	return res
}

// describeTransportError strips the request URL from url.Error so query-string
// tokens do not end up in the result document or logs.
func describeTransportError(err error) string {
	if errors.Is(err, context.DeadlineExceeded) {
		return "request timed out"
	}
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		return urlErr.Op + ": " + urlErr.Err.Error()
	}
	return err.Error()
}
