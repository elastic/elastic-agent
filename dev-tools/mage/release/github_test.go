// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package release

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/go-github/v93/github"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestGitHubClient(t *testing.T, handler http.Handler) *GitHubClient {
	t.Helper()

	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	baseURL := server.URL + "/"
	client, err := github.NewClient(
		github.WithHTTPClient(server.Client()),
		github.WithURLs(&baseURL, &baseURL),
	)
	require.NoError(t, err)

	return &GitHubClient{
		client: client,
		ctx:    context.Background(),
	}
}

func TestCreatePRIdempotent(t *testing.T) {
	createCalls := 0
	existingPR := &github.PullRequest{
		Number:  new(42),
		HTMLURL: new("https://github.com/elastic/elastic-agent/pull/42"),
		Head: &github.PullRequestBranch{
			Ref: new("9.5"),
		},
		Base: &github.PullRequestBranch{
			Ref: new("main"),
		},
		State: new("open"),
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/repos/elastic/elastic-agent/pulls":
			w.Header().Set("Content-Type", "application/json")
			require.NoError(t, json.NewEncoder(w).Encode([]*github.PullRequest{existingPR}))
		case r.Method == http.MethodPost && r.URL.Path == "/repos/elastic/elastic-agent/pulls":
			createCalls++
			w.WriteHeader(http.StatusUnprocessableEntity)
			_, _ = fmt.Fprint(w, `{"message":"Validation Failed","errors":[{"message":"A pull request already exists for elastic:9.5."}]}`)
		default:
			assert.Failf(t, "unexpected request", "%s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	})

	ghClient := newTestGitHubClient(t, handler)
	opts := PROptions{
		Owner: "elastic",
		Repo:  "elastic-agent",
		Title: "[Release][9.5.0] Prepare release branch",
		Head:  "9.5",
		Base:  "main",
		Body:  "Release PR body",
	}

	pr, err := ghClient.CreatePR(opts)
	require.NoError(t, err)
	require.Equal(t, 42, pr.GetNumber())
	require.Equal(t, 0, createCalls)

	pr2, err := ghClient.CreatePR(opts)
	require.NoError(t, err)
	require.Equal(t, pr.GetNumber(), pr2.GetNumber())
	require.Equal(t, 0, createCalls)
}

func TestCreatePRCreatesWhenNoneExists(t *testing.T) {
	createCalls := 0
	newPR := &github.PullRequest{
		Number:  new(99),
		HTMLURL: new("https://github.com/elastic/elastic-agent/pull/99"),
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/repos/elastic/elastic-agent/pulls":
			w.Header().Set("Content-Type", "application/json")
			require.NoError(t, json.NewEncoder(w).Encode([]*github.PullRequest{}))
		case r.Method == http.MethodPost && r.URL.Path == "/repos/elastic/elastic-agent/pulls":
			createCalls++
			w.Header().Set("Content-Type", "application/json")
			require.NoError(t, json.NewEncoder(w).Encode(newPR))
		default:
			assert.Failf(t, "unexpected request", "%s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	})

	ghClient := newTestGitHubClient(t, handler)
	pr, err := ghClient.CreatePR(PROptions{
		Owner: "elastic",
		Repo:  "elastic-agent",
		Title: "New release PR",
		Head:  "9.6",
		Base:  "main",
		Body:  "body",
	})
	require.NoError(t, err)
	require.Equal(t, 99, pr.GetNumber())
	require.Equal(t, 1, createCalls)
}

func TestCreatePRFailsWhenLabelsCannotBeAdded(t *testing.T) {
	existingPR := &github.PullRequest{
		Number:  new(42),
		HTMLURL: new("https://github.com/elastic/elastic-agent/pull/42"),
		Head: &github.PullRequestBranch{
			Ref: new("ff-prep-main-9.5.0"),
		},
		Base: &github.PullRequestBranch{
			Ref: new("main"),
		},
		State: new("open"),
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/repos/elastic/elastic-agent/pulls":
			w.Header().Set("Content-Type", "application/json")
			require.NoError(t, json.NewEncoder(w).Encode([]*github.PullRequest{existingPR}))
		case r.Method == http.MethodGet && r.URL.Path == "/repos/elastic/elastic-agent/labels/"+mergeLabelFFDay:
			w.Header().Set("Content-Type", "application/json")
			require.NoError(t, json.NewEncoder(w).Encode(&github.Label{Name: mergeLabelFFDay}))
		case r.Method == http.MethodPost && r.URL.Path == "/repos/elastic/elastic-agent/issues/42/labels":
			w.WriteHeader(http.StatusForbidden)
			_, _ = fmt.Fprint(w, `{"message":"Resource not accessible by integration"}`)
		default:
			assert.Failf(t, "unexpected request", "%s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	})

	ghClient := newTestGitHubClient(t, handler)
	_, err := ghClient.CreatePR(PROptions{
		Owner:  "elastic",
		Repo:   "elastic-agent",
		Title:  "[Release][9.5.0] Prepare main",
		Head:   "ff-prep-main-9.5.0",
		Base:   "main",
		Body:   "body",
		Labels: []string{mergeLabelFFDay},
	})
	require.Error(t, err, "CreatePR() should fail when labels cannot be added")
	require.ErrorContains(t, err, "failed to add labels")
}
