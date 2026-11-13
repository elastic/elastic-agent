// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package workflowrunner

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const secretToken = "Bearer super-secret-token"

type indexedDoc struct {
	index string
	id    string
	doc   map[string]interface{}
}

type fakeIndexer struct {
	mu   sync.Mutex
	docs []indexedDoc
	err  error
}

func (f *fakeIndexer) Index(_ context.Context, index, id string, doc any) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	f.docs = append(f.docs, indexedDoc{index: index, id: id, doc: doc.(map[string]interface{})})
	return nil
}

func newTestAction(t *testing.T, dir string, indexer Indexer) *httpAction {
	t.Helper()
	store, err := OpenStore(dir)
	require.NoError(t, err)
	return &httpAction{
		logger:   zerolog.Nop(),
		executor: NewExecutor(),
		store:    store,
		target:   func() (Indexer, string) { return indexer, "default" },
	}
}

func actionParams(id, method, url string, headers map[string]string, body string) map[string]interface{} {
	return map[string]interface{}{
		"id":         id,
		"type":       "INPUT_ACTION",
		"input_type": ActionName,
		"timeout":    float64(10),
		"data": map[string]interface{}{
			"execution_id": "exec-1",
			"step_id":      "call-jenkins",
			"request": map[string]interface{}{
				"method":  method,
				"url":     url,
				"headers": headers,
				"body":    body,
			},
		},
	}
}

func TestExecuteIndexesResultWithoutCredentials(t *testing.T) {
	var gotAuth, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Set-Cookie", "session=abc")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"queued":true}`))
	}))
	defer srv.Close()

	indexer := &fakeIndexer{}
	a := newTestAction(t, t.TempDir(), indexer)

	ack, err := a.Execute(t.Context(), actionParams("action-1", http.MethodPost, srv.URL+"/job/build",
		map[string]string{"Authorization": secretToken}, `{"branch":"main"}`))
	require.NoError(t, err)

	assert.Equal(t, secretToken, gotAuth, "credential must reach the target")
	assert.Equal(t, `{"branch":"main"}`, gotBody)

	assert.Equal(t, http.StatusCreated, ack["status_code"])
	assert.Equal(t, "action-1", ack["result_id"])
	assert.Equal(t, "logs-workflow_runner.http-default", ack["result_index"])
	assert.NotContains(t, ack, "error")

	require.Len(t, indexer.docs, 1)
	stored := indexer.docs[0]
	assert.Equal(t, "logs-workflow_runner.http-default", stored.index)
	assert.Equal(t, "action-1", stored.id)

	resp := stored.doc["http"].(map[string]interface{})["response"].(map[string]interface{})
	assert.Equal(t, http.StatusCreated, resp["status_code"])
	assert.Equal(t, `{"queued":true}`, resp["body"].(map[string]interface{})["content"])
	assert.NotContains(t, resp["headers"], "Set-Cookie")

	for name, v := range map[string]any{"result document": stored.doc, "ack": ack} {
		raw, err := json.Marshal(v)
		require.NoError(t, err)
		assert.NotContains(t, string(raw), "super-secret-token", "%s must not contain the credential", name)
		assert.NotContains(t, string(raw), `"branch"`, "%s must not contain the request body", name)
	}
}

func TestExecuteDecodesBase64BodyAndRecordsSpace(t *testing.T) {
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
	}))
	defer srv.Close()

	indexer := &fakeIndexer{}
	params := actionParams("action-b64", http.MethodPost, srv.URL, nil, "AP8Q")
	data := params["data"].(map[string]interface{})
	data["space_id"] = "team-a"
	data["request"].(map[string]interface{})["body_encoding"] = "base64"

	_, err := newTestAction(t, t.TempDir(), indexer).Execute(t.Context(), params)
	require.NoError(t, err)

	assert.Equal(t, []byte{0x00, 0xff, 0x10}, gotBody)
	require.Len(t, indexer.docs, 1)
	assert.Equal(t, "team-a", indexer.docs[0].doc["workflow"].(map[string]interface{})["space_id"])
}

func TestExecuteDuplicateActionDoesNotRepeatCall(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	dir := t.TempDir()
	indexer := &fakeIndexer{}
	params := actionParams("action-dup", http.MethodPost, srv.URL, nil, "")

	first, err := newTestAction(t, dir, indexer).Execute(t.Context(), params)
	require.NoError(t, err)

	// A redelivery after the component restarts reads the store from disk.
	second, err := newTestAction(t, dir, indexer).Execute(t.Context(), params)
	require.NoError(t, err)

	assert.Equal(t, int32(1), calls.Load(), "a redelivered action must not repeat the HTTP call")
	assert.Equal(t, first["result_id"], second["result_id"])
	assert.Len(t, indexer.docs, 1)
}

func TestExecuteTransportErrorIsStoredAndReported(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL
	srv.Close()

	indexer := &fakeIndexer{}
	a := newTestAction(t, t.TempDir(), indexer)

	ack, err := a.Execute(t.Context(), actionParams("action-down", http.MethodGet, url, nil, ""))
	require.NoError(t, err, "a failed HTTP call is a step result, not an invalid action")

	require.Contains(t, ack, "error")
	assert.NotContains(t, ack, "status_code")
	assert.Equal(t, "action-down", ack["result_id"])

	require.Len(t, indexer.docs, 1)
	doc := indexer.docs[0].doc
	assert.Equal(t, "failure", doc["event"].(map[string]interface{})["outcome"])
	assert.Equal(t, ack["error"], doc["error"].(map[string]interface{})["message"])
}

func TestExecuteIndexFailureIsReported(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	a := newTestAction(t, t.TempDir(), &fakeIndexer{err: errors.New("403 forbidden")})

	ack, err := a.Execute(t.Context(), actionParams("action-noindex", http.MethodGet, srv.URL, nil, ""))
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, ack["status_code"])
	assert.Contains(t, ack["error"], "403 forbidden")
	assert.NotContains(t, ack, "result_id")
}

func TestExecuteRejectsInvalidActions(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
	}))
	defer srv.Close()

	cases := map[string]map[string]interface{}{
		"missing id":     actionParams("", http.MethodGet, srv.URL, nil, ""),
		"file scheme":    actionParams("a", http.MethodGet, "file:///etc/passwd", nil, ""),
		"unknown method": actionParams("a", "CONNECT", srv.URL, nil, ""),
		"no host":        actionParams("a", http.MethodGet, "http:///path", nil, ""),
		"credentials in url": actionParams("a", http.MethodGet,
			strings.Replace(srv.URL, "http://", "http://user:pass@", 1), nil, ""),
	}
	tooLong := actionParams("a", http.MethodGet, srv.URL, nil, "")
	tooLong["timeout"] = float64(2 * 60 * 60)
	cases["timeout over maximum"] = tooLong

	withRequest := func(field string, value interface{}) map[string]interface{} {
		p := actionParams("a", http.MethodPost, srv.URL, nil, "not base64!")
		p["data"].(map[string]interface{})["request"].(map[string]interface{})[field] = value
		return p
	}
	cases["unknown body encoding"] = withRequest("body_encoding", "gzip")
	cases["invalid base64 body"] = withRequest("body_encoding", "base64")
	cases["too many redirects"] = withRequest("max_redirects", float64(11))
	cases["negative redirects"] = withRequest("max_redirects", float64(-1))
	cases["negative max response bytes"] = withRequest("max_response_bytes", float64(-1))

	indexer := &fakeIndexer{}
	a := newTestAction(t, t.TempDir(), indexer)
	for name, params := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := a.Execute(t.Context(), params)
			assert.Error(t, err)
		})
	}
	assert.Zero(t, calls.Load(), "invalid actions must not reach the network")
	assert.Empty(t, indexer.docs)
}

func TestExecuteWithoutOutputReportsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	store, err := OpenStore(t.TempDir())
	require.NoError(t, err)
	a := &httpAction{
		logger:   zerolog.Nop(),
		executor: NewExecutor(),
		store:    store,
		target:   func() (Indexer, string) { return nil, "" },
	}

	ack, err := a.Execute(t.Context(), actionParams("action-nooutput", http.MethodGet, srv.URL, nil, ""))
	require.NoError(t, err)
	assert.Contains(t, ack["error"], "no elasticsearch output")
}
