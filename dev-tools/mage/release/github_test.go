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
	"net/url"
	"testing"

	"github.com/google/go-github/v68/github"
)

func newTestGitHubClient(t *testing.T, handler http.Handler) *GitHubClient {
	t.Helper()

	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	client := github.NewClient(server.Client())
	baseURL, err := url.Parse(server.URL + "/")
	if err != nil {
		t.Fatalf("failed to parse test server URL: %v", err)
	}
	client.BaseURL = baseURL
	client.UploadURL = baseURL

	return &GitHubClient{
		client: client,
		ctx:    context.Background(),
	}
}

func TestCreatePRIdempotent(t *testing.T) {
	createCalls := 0
	existingPR := &github.PullRequest{
		Number:  github.Ptr(42),
		HTMLURL: github.Ptr("https://github.com/elastic/elastic-agent/pull/42"),
		Head: &github.PullRequestBranch{
			Ref: github.Ptr("9.5"),
		},
		Base: &github.PullRequestBranch{
			Ref: github.Ptr("main"),
		},
		State: github.Ptr("open"),
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/repos/elastic/elastic-agent/pulls":
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode([]*github.PullRequest{existingPR}); err != nil {
				t.Errorf("failed to encode PR list response: %v", err)
			}
		case r.Method == http.MethodPost && r.URL.Path == "/repos/elastic/elastic-agent/pulls":
			createCalls++
			w.WriteHeader(http.StatusUnprocessableEntity)
			_, _ = fmt.Fprint(w, `{"message":"Validation Failed","errors":[{"message":"A pull request already exists for elastic:9.5."}]}`)
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	})

	ghClient := newTestGitHubClient(t, handler)
	opts := PROptions{
		Owner: "elastic",
		Repo:  "elastic-agent",
		Title: "[Release 9.5.0] Prepare release branch",
		Head:  "9.5",
		Base:  "main",
		Body:  "Release PR body",
	}

	pr, err := ghClient.CreatePR(opts)
	if err != nil {
		t.Fatalf("CreatePR() error = %v", err)
	}

	if pr.GetNumber() != 42 {
		t.Errorf("CreatePR() number = %d, want 42", pr.GetNumber())
	}
	if createCalls != 0 {
		t.Errorf("CreatePR() called create API %d times, want 0", createCalls)
	}

	pr2, err := ghClient.CreatePR(opts)
	if err != nil {
		t.Fatalf("CreatePR() second call error = %v", err)
	}
	if pr2.GetNumber() != pr.GetNumber() {
		t.Errorf("CreatePR() second call number = %d, want %d", pr2.GetNumber(), pr.GetNumber())
	}
	if createCalls != 0 {
		t.Errorf("CreatePR() called create API %d times after second call, want 0", createCalls)
	}
}

func TestCreatePRCreatesWhenNoneExists(t *testing.T) {
	createCalls := 0
	newPR := &github.PullRequest{
		Number:  github.Ptr(99),
		HTMLURL: github.Ptr("https://github.com/elastic/elastic-agent/pull/99"),
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/repos/elastic/elastic-agent/pulls":
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode([]*github.PullRequest{}); err != nil {
				t.Errorf("failed to encode empty PR list response: %v", err)
			}
		case r.Method == http.MethodPost && r.URL.Path == "/repos/elastic/elastic-agent/pulls":
			createCalls++
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(newPR); err != nil {
				t.Errorf("failed to encode create PR response: %v", err)
			}
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
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
	if err != nil {
		t.Fatalf("CreatePR() error = %v", err)
	}
	if pr.GetNumber() != 99 {
		t.Errorf("CreatePR() number = %d, want 99", pr.GetNumber())
	}
	if createCalls != 1 {
		t.Errorf("CreatePR() called create API %d times, want 1", createCalls)
	}
}
