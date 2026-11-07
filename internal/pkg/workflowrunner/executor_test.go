// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package workflowrunner

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func mustParseURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	require.NoError(t, err)
	return u
}

func getCall(t *testing.T, raw string) Call {
	return Call{Method: http.MethodGet, Target: mustParseURL(t, raw)}
}

// redirectServer redirects /hop/N to /hop/N-1 and answers /hop/0 with "done".
func redirectServer(t *testing.T) (*httptest.Server, *[]string) {
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.URL.Path)
		switch r.URL.Path {
		case "/hop/0":
			_, _ = w.Write([]byte("done"))
		case "/hop/1":
			http.Redirect(w, r, "/hop/0", http.StatusFound)
		case "/hop/2":
			http.Redirect(w, r, "/hop/1", http.StatusFound)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &seen
}

func TestExecutorDoesNotFollowRedirectsByDefault(t *testing.T) {
	srv, seen := redirectServer(t)

	res := NewExecutor().Do(t.Context(), getCall(t, srv.URL+"/hop/1"))

	assert.Empty(t, res.Error)
	assert.Equal(t, http.StatusFound, res.StatusCode)
	assert.Equal(t, "/hop/0", res.Headers["Location"])
	assert.Equal(t, []string{"/hop/1"}, *seen, "redirect target must not be requested")
}

func TestExecutorFollowsRedirectsUpToLimit(t *testing.T) {
	srv, seen := redirectServer(t)

	call := getCall(t, srv.URL+"/hop/2")
	call.MaxRedirects = 2
	res := NewExecutor().Do(t.Context(), call)
	assert.Empty(t, res.Error)
	assert.Equal(t, http.StatusOK, res.StatusCode)
	assert.Equal(t, "done", res.Body)

	*seen = nil
	call.MaxRedirects = 1
	res = NewExecutor().Do(t.Context(), call)
	assert.Equal(t, http.StatusFound, res.StatusCode, "stops at the last allowed hop")
	assert.Equal(t, []string{"/hop/2", "/hop/1"}, *seen)
}

func TestExecutorDropsAuthorizationOnCrossHostRedirect(t *testing.T) {
	var gotAuth string
	other := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
	}))
	defer other.Close()
	// 127.0.0.1 and localhost are different hosts to net/http.
	otherURL := strings.Replace(other.URL, "127.0.0.1", "localhost", 1)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, otherURL, http.StatusFound)
	}))
	defer origin.Close()

	call := getCall(t, origin.URL)
	call.Headers = map[string]string{"Authorization": "Bearer secret"}
	call.MaxRedirects = 1
	res := NewExecutor().Do(t.Context(), call)

	assert.Empty(t, res.Error)
	assert.Equal(t, http.StatusOK, res.StatusCode)
	assert.Empty(t, gotAuth)
}

func TestExecutorSendsBinaryBody(t *testing.T) {
	var got []byte
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		got, _ = io.ReadAll(r.Body)
	}))
	defer srv.Close()

	body := []byte{0x00, 0xff, 0x10}
	_ = NewExecutor().Do(t.Context(), Call{Method: http.MethodPost, Target: mustParseURL(t, srv.URL), Body: body})

	assert.Equal(t, body, got)
}

func TestExecutorTruncatesLargeBodies(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("a", 64)))
	}))
	defer srv.Close()

	e := NewExecutor()
	e.maxBodyBytes = 16
	res := e.Do(t.Context(), getCall(t, srv.URL))
	assert.Empty(t, res.Error)
	assert.True(t, res.Truncated)
	assert.Equal(t, int64(16), res.BodyBytes)
	assert.Len(t, res.Body, 16)

	call := getCall(t, srv.URL)
	call.MaxResponseBytes = 8
	res = e.Do(t.Context(), call)
	assert.Equal(t, int64(8), res.BodyBytes, "a lower per-request cap applies")

	call.MaxResponseBytes = 1 << 30
	res = e.Do(t.Context(), call)
	assert.Equal(t, int64(16), res.BodyBytes, "a per-request cap can't raise the executor cap")
}

func TestExecutorTimeout(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()
	defer close(release)

	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	res := NewExecutor().Do(ctx, getCall(t, srv.URL))

	assert.Equal(t, "request timed out", res.Error)
	assert.Zero(t, res.StatusCode)
}

func TestExecutorErrorOmitsURLQuery(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	target := srv.URL + "/hook?token=query-secret"
	srv.Close()

	res := NewExecutor().Do(t.Context(), getCall(t, target))

	require.NotEmpty(t, res.Error)
	assert.NotContains(t, res.Error, "query-secret")
}
