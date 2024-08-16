// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package downloads

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
)

// httpRequest configures an HTTP request
type httpRequest struct {
	BasicAuthUser     string
	BasicAuthPassword string
	EncodeURL         bool
	Headers           map[string]string
	method            string
	Payload           string // string representation of fthe payload, in JSON format
	QueryString       string
	URL               string
}

// GetURL returns the URL as a string
func (req *httpRequest) GetURL() string {
	if req.QueryString == "" {
		return req.URL
	}

	u := req.URL + "?"
	if req.EncodeURL {
		return u + url.QueryEscape(req.QueryString)
	}

	return u + req.QueryString
}

// delete executes a DELETE request
//
//nolint:unused // defined for completeness of HTTP methods
func delete(r httpRequest) (string, error) {
	r.method = "DELETE"

	return request(r)
}

// head executes a HEAD request
func head(r httpRequest) (string, error) {
	r.method = "HEAD"

	return request(r)
}

// get executes a GET request
func get(r httpRequest) (string, error) {
	r.method = "GET"

	return request(r)
}

// post executes a POST request
//
//nolint:unused // defined for completeness of HTTP methods
func post(r httpRequest) (string, error) {
	r.method = "POST"

	return request(r)
}

// put executes a PUT request
//
//nolint:unused // defined for completeness of HTTP methods
func put(r httpRequest) (string, error) {
	r.method = "PUT"

	return request(r)
}

// request executes a request
func request(r httpRequest) (string, error) {
	escapedURL := r.GetURL()

	fields := []any{
		slog.String("method", r.method),
		slog.String("escapedURL", escapedURL),
	}

	var body io.Reader
	if r.Payload != "" {
		body = bytes.NewReader([]byte(r.Payload))
		fields = append(fields, slog.String("payload", r.Payload))
	} else {
		body = nil
	}

	logger.Log(context.Background(), TraceLevel, "Executing request", fields...)

	req, err := http.NewRequestWithContext(context.TODO(), r.method, escapedURL, body)
	if err != nil {
		logger.Warn("Error creating request",
			slog.String("error", err.Error()),
			slog.String("method", r.method),
			slog.String("escapedURL", escapedURL),
		)
		return "", err
	}

	if r.Headers != nil {
		for k, v := range r.Headers {
			req.Header.Set(k, v)
		}
	}

	if r.BasicAuthUser != "" {
		req.SetBasicAuth(r.BasicAuthUser, r.BasicAuthPassword)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		logger.Warn("Error executing request",
			slog.String("error", err.Error()),
			slog.String("method", r.method),
			slog.String("escapedURL", escapedURL),
		)
		return "", err
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		logger.Warn("Could not read response body",
			slog.String("error", err.Error()),
			slog.String("method", r.method),
			slog.String("escapedURL", escapedURL),
		)
		return "", err
	}
	bodyString := string(bodyBytes)

	// http.Status ==> [2xx, 4xx)
	if resp.StatusCode >= http.StatusOK && resp.StatusCode < http.StatusBadRequest {
		return bodyString, nil
	}

	return bodyString, fmt.Errorf("%s request failed with %d", r.method, resp.StatusCode)
}
