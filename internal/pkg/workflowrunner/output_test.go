// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package workflowrunner

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type esRequest struct {
	method string
	path   string
	query  string
	auth   string
	body   map[string]interface{}
}

type fakeES struct {
	*httptest.Server
	mu   sync.Mutex
	reqs []esRequest
}

func (f *fakeES) requests() []esRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]esRequest(nil), f.reqs...)
}

func newFakeES(t *testing.T, status int) *fakeES {
	t.Helper()
	f := &fakeES{}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var body map[string]interface{}
		_ = json.Unmarshal(raw, &body)
		f.mu.Lock()
		defer f.mu.Unlock()
		f.reqs = append(f.reqs, esRequest{
			method: r.Method,
			path:   r.URL.Path,
			query:  r.URL.RawQuery,
			auth:   r.Header.Get("Authorization"),
			body:   body,
		})
		w.Header().Set("X-Elastic-Product", "Elasticsearch")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(f.Close)
	return f
}

func TestESIndexerUsesOutputAPIKey(t *testing.T) {
	srv := newFakeES(t, http.StatusCreated)

	indexer, err := newESIndexer(map[string]interface{}{
		"type":    "elasticsearch",
		"hosts":   []interface{}{srv.URL},
		"api_key": "key-id:key-secret",
	})
	require.NoError(t, err)

	require.NoError(t, indexer.Index(t.Context(), "logs-workflow_runner.http-default", "action-1",
		map[string]interface{}{"@timestamp": "2026-10-11T00:00:00Z"}))

	reqs := srv.requests()
	require.Len(t, reqs, 1)
	r := reqs[0]
	assert.Equal(t, http.MethodPut, r.method)
	assert.Equal(t, "/logs-workflow_runner.http-default/_doc/action-1", r.path)
	assert.Contains(t, r.query, "op_type=create")
	assert.Contains(t, r.query, "refresh=wait_for")
	// Elasticsearch matches the auth scheme case-insensitively; go-elasticsearch sends "APIKey".
	assert.True(t, strings.EqualFold("ApiKey "+base64.StdEncoding.EncodeToString([]byte("key-id:key-secret")), r.auth),
		"unexpected Authorization header %q", r.auth)
}

func TestESIndexerTreatsConflictAsStored(t *testing.T) {
	srv := newFakeES(t, http.StatusConflict)

	indexer, err := newESIndexer(map[string]interface{}{
		"type":  "elasticsearch",
		"hosts": []interface{}{srv.URL},
	})
	require.NoError(t, err)
	assert.NoError(t, indexer.Index(t.Context(), "idx", "id", map[string]interface{}{}))
}

func TestESIndexerReportsErrors(t *testing.T) {
	srv := newFakeES(t, http.StatusForbidden)

	indexer, err := newESIndexer(map[string]interface{}{
		"type":  "elasticsearch",
		"hosts": []interface{}{srv.URL},
	})
	require.NoError(t, err)
	err = indexer.Index(t.Context(), "idx", "id", map[string]interface{}{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "403")
}

func TestNewESIndexerRejectsUnsupportedOutputs(t *testing.T) {
	_, err := newESIndexer(map[string]interface{}{"type": "logstash", "hosts": []interface{}{"localhost:5044"}})
	assert.ErrorContains(t, err, "unsupported output type")

	_, err = newESIndexer(map[string]interface{}{"type": "elasticsearch"})
	assert.ErrorContains(t, err, "no hosts")
}

func TestHostURLs(t *testing.T) {
	assert.Equal(t,
		[]string{"https://es.example:9200/prefix", "https://other:443/prefix"},
		hostURLs([]string{"es.example:9200", "https://other:443/"}, "https", "/prefix/"))
	assert.Equal(t, []string{"http://localhost:9200"}, hostURLs([]string{"localhost:9200"}, "", ""))
}

func TestEncodeAPIKey(t *testing.T) {
	assert.Equal(t, base64.StdEncoding.EncodeToString([]byte("id:key")), encodeAPIKey("id:key"))
	assert.Equal(t, "already-encoded", encodeAPIKey("already-encoded"))
	assert.Empty(t, encodeAPIKey(""))
}
