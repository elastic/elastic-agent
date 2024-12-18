// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package http

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-libs/logp"
)

func TestVerifyBackoffRoundtripper(t *testing.T) {
	t.Run("test get request retry", func(t *testing.T) {
		failedResCounter := 2
		handler := func(rw http.ResponseWriter, req *http.Request) {
			if failedResCounter > 0 {
				rw.WriteHeader(http.StatusInternalServerError)
				failedResCounter--
			}
			_, err := rw.Write([]byte("hello"))
			require.NoError(t, err)
		}
		server := httptest.NewServer(http.HandlerFunc(handler))
		client := http.Client{
			Transport: WithBackoff(&http.Transport{}, logp.NewLogger("testing")),
			Timeout:   10 * time.Second,
		}

		res, err := client.Get(server.URL) //nolint:noctx // test code
		require.NoError(t, err)
		defer res.Body.Close()

		body, err := io.ReadAll(res.Body)
		require.NoError(t, err)

		require.Equal(t, string(body), "hello")
		require.Equal(t, res.StatusCode, 200)
		require.Equal(t, failedResCounter, 0)
	})

	t.Run("test post request with body", func(t *testing.T) {
		failedResCounter := 2
		handler := func(rw http.ResponseWriter, req *http.Request) {
			if failedResCounter > 0 {
				rw.WriteHeader(http.StatusInternalServerError)
				failedResCounter--
			}

			body, err := io.ReadAll(req.Body)
			require.NoError(t, err)
			defer req.Body.Close()

			_, err = rw.Write(body)
			require.NoError(t, err)
		}
		server := httptest.NewServer(http.HandlerFunc(handler))
		client := http.Client{
			Transport: WithBackoff(&http.Transport{}, logp.NewLogger("testing")),
			Timeout:   10 * time.Second,
		}

		reqReader := bytes.NewReader([]byte("hello"))

		resp, err := client.Post(server.URL, "text/html", reqReader) //nolint:noctx // test code
		require.NoError(t, err)
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)

		require.Equal(t, string(body), "hello")
		require.Equal(t, resp.StatusCode, 200)
		require.Equal(t, failedResCounter, 0)
	})
}
