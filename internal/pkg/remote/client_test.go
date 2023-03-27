// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package remote

import (
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/internal/pkg/config"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

func noopWrapper(rt http.RoundTripper) (http.RoundTripper, error) {
	return rt, nil
}

func addCatchAll(mux *http.ServeMux, t *testing.T) *http.ServeMux {
	mux.HandleFunc("/", func(_ http.ResponseWriter, _ *http.Request) {
		t.Fatal("HTTP catch all handled called")
	})
	return mux
}

func TestPortDefaults(t *testing.T) {
	l, err := logger.New("", false)
	require.NoError(t, err)

	testCases := []struct {
		Name           string
		URI            string
		ExpectedPort   int
		ExpectedScheme string
	}{
		{"no scheme uri", "test.url", 0, "http"},
		{"default port", "http://test.url", 0, "http"},
		{"specified port", "http://test.url:123", 123, "http"},
		{"default https port", "https://test.url", 0, "https"},
		{"specified https port", "https://test.url:123", 123, "https"},
	}
	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			cfg, err := NewConfigFromURL(tc.URI)
			require.NoError(t, err)

			c, err := NewWithConfig(l, cfg, nil)
			require.NoError(t, err)

			clients := c.sortClients()
			r, err := clients[0].newRequest(http.MethodGet, "/", nil, strings.NewReader(""))
			require.NoError(t, err)

			if tc.ExpectedPort > 0 {
				assert.True(t, strings.HasSuffix(r.Host, fmt.Sprintf(":%d", tc.ExpectedPort)))
			} else {
				assert.False(t, strings.HasSuffix(r.Host, fmt.Sprintf(":%d", tc.ExpectedPort)))
			}
			assert.Equal(t, tc.ExpectedScheme, r.URL.Scheme)
		})
	}
}

// - Prefix.
func TestHTTPClient(t *testing.T) {
	ctx := context.Background()
	l, err := logger.New("", false)
	require.NoError(t, err)

	const successResp = `{"message":"hello"}`
	t.Run("Guard against double slashes on path", withServer(
		func(t *testing.T) *http.ServeMux {
			mux := http.NewServeMux()
			mux.HandleFunc("/nested/echo-hello", func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				fmt.Fprint(w, successResp)
			})
			return addCatchAll(mux, t)
		}, func(t *testing.T, host string) {
			// Add a slashes at the end of the URL, internally we should prevent having double slashes
			// when adding path to the request.
			url := "http://" + host + "/"

			c, err := NewConfigFromURL(url)
			require.NoError(t, err)

			client, err := NewWithConfig(l, c, noopWrapper)
			require.NoError(t, err)

			resp, err := client.Send(ctx, http.MethodGet, "/nested/echo-hello", nil, nil, nil)
			require.NoError(t, err)

			body, err := ioutil.ReadAll(resp.Body)
			require.NoError(t, err)
			defer resp.Body.Close()
			assert.Equal(t, successResp, string(body))
		},
	))

	t.Run("Simple call", withServer(
		func(t *testing.T) *http.ServeMux {
			mux := http.NewServeMux()
			mux.HandleFunc("/echo-hello", func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				fmt.Fprint(w, successResp)
			})
			return mux
		}, func(t *testing.T, host string) {
			cfg := config.MustNewConfigFrom(map[string]interface{}{
				"host": host,
			})

			client, err := NewWithRawConfig(nil, cfg, nil)
			require.NoError(t, err)
			resp, err := client.Send(ctx, http.MethodGet, "/echo-hello", nil, nil, nil)
			require.NoError(t, err)

			body, err := ioutil.ReadAll(resp.Body)
			require.NoError(t, err)
			defer resp.Body.Close()
			assert.Equal(t, successResp, string(body))
		},
	))

	t.Run("Simple call with a prefix path", withServer(
		func(t *testing.T) *http.ServeMux {
			mux := http.NewServeMux()
			mux.HandleFunc("/mycustompath/echo-hello", func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				fmt.Fprint(w, successResp)
			})
			return mux
		}, func(t *testing.T, host string) {
			cfg := config.MustNewConfigFrom(map[string]interface{}{
				"host": host,
				"path": "mycustompath",
			})

			client, err := NewWithRawConfig(nil, cfg, nil)
			require.NoError(t, err)
			resp, err := client.Send(ctx, http.MethodGet, "/echo-hello", nil, nil, nil)
			require.NoError(t, err)

			body, err := ioutil.ReadAll(resp.Body)
			require.NoError(t, err)
			defer resp.Body.Close()
			assert.Equal(t, successResp, string(body))
		},
	))

	t.Run("Tries all the hosts", withServer(
		func(t *testing.T) *http.ServeMux {
			mux := http.NewServeMux()
			mux.HandleFunc("/echo-hello", func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				fmt.Fprint(w, successResp)
			})
			return mux
		}, func(t *testing.T, host string) {
			one := &requestClient{host: "http://must.fail-1.co/"}
			two := &requestClient{host: "http://must.fail-2.co/"}
			three := &requestClient{host: fmt.Sprintf("http://%s/", host)}

			c := &Client{clients: []*requestClient{one, two, three}, log: l}
			require.NoError(t, err)
			resp, err := c.Send(ctx, http.MethodGet, "/echo-hello", nil, nil, nil)
			require.NoError(t, err)

			assert.Equal(t, http.StatusOK, resp.StatusCode)
			body, err := ioutil.ReadAll(resp.Body)
			require.NoError(t, err)
			defer resp.Body.Close()
			assert.Equal(t, successResp, string(body))
		},
	))

	t.Run("Return last error", func(t *testing.T) {
		client := &Client{
			log: l,
			clients: []*requestClient{
				{host: "http://must.fail-1.co/"},
				{host: "http://must.fail-2.co/"},
				{host: "http://must.fail-3.co/"},
			}}

		resp, err := client.Send(ctx, http.MethodGet, "/echo-hello", nil, nil, nil) //nolint:bodyclose // wad
		assert.Contains(t, err.Error(), "http://must.fail-3.co/")                   // error contains last host
		assert.Nil(t, resp)
	})

	t.Run("Custom user agent", withServer(
		func(t *testing.T) *http.ServeMux {
			mux := http.NewServeMux()
			mux.HandleFunc("/echo-hello", func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				fmt.Fprint(w, successResp)
				require.Equal(t, r.Header.Get("User-Agent"), "custom-agent")
			})
			return mux
		}, func(t *testing.T, host string) {
			cfg := config.MustNewConfigFrom(map[string]interface{}{
				"host": host,
			})

			client, err := NewWithRawConfig(nil, cfg, func(wrapped http.RoundTripper) (http.RoundTripper, error) {
				return NewUserAgentRoundTripper(wrapped, "custom-agent"), nil
			})

			require.NoError(t, err)
			resp, err := client.Send(ctx, http.MethodGet, "/echo-hello", nil, nil, nil)
			require.NoError(t, err)

			body, err := ioutil.ReadAll(resp.Body)
			require.NoError(t, err)
			defer resp.Body.Close()
			assert.Equal(t, successResp, string(body))
		},
	))

	t.Run("Allows to debug HTTP request between a client and a server", withServer(
		func(t *testing.T) *http.ServeMux {
			mux := http.NewServeMux()
			mux.HandleFunc("/echo-hello", func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				fmt.Fprint(w, successResp)
			})
			return mux
		}, func(t *testing.T, host string) {

			debugger := &debugStack{}

			cfg := config.MustNewConfigFrom(map[string]interface{}{
				"host": host,
			})

			client, err := NewWithRawConfig(nil, cfg, func(wrapped http.RoundTripper) (http.RoundTripper, error) {
				return NewDebugRoundTripper(wrapped, debugger), nil
			})

			require.NoError(t, err)
			resp, err := client.Send(ctx, http.MethodGet, "/echo-hello", nil, nil, bytes.NewBuffer([]byte("hello")))
			require.NoError(t, err)

			body, err := ioutil.ReadAll(resp.Body)
			require.NoError(t, err)
			defer resp.Body.Close()
			assert.Equal(t, successResp, string(body))

			for _, m := range debugger.messages {
				fmt.Println(m) //nolint:forbidigo // printing debug messages on a test.
			}

			assert.Equal(t, 1, len(debugger.messages))
		},
	))

	t.Run("RequestId", withServer(
		func(t *testing.T) *http.ServeMux {
			mux := http.NewServeMux()
			mux.HandleFunc("/echo-hello", func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				fmt.Fprint(w, successResp)
				require.NotEmpty(t, r.Header.Get("X-Request-ID"))
			})
			return mux
		}, func(t *testing.T, host string) {
			cfg := config.MustNewConfigFrom(map[string]interface{}{
				"host": host,
			})

			client, err := NewWithRawConfig(nil, cfg, nil)
			require.NoError(t, err)
			resp, err := client.Send(ctx, http.MethodGet, "/echo-hello", nil, nil, nil)
			require.NoError(t, err)

			body, err := ioutil.ReadAll(resp.Body)
			require.NoError(t, err)
			defer resp.Body.Close()
			assert.Equal(t, successResp, string(body))
		},
	))
}

func TestSortClients(t *testing.T) {
	t.Run("Picks first requester on initial call", func(t *testing.T) {
		one := &requestClient{}
		two := &requestClient{}
		client, err := newClient(nil, Config{}, one, two)
		require.NoError(t, err)

		clients := client.sortClients()

		assert.Equal(t, one, clients[0])
	})

	t.Run("Picks second requester when first has error", func(t *testing.T) {
		one := &requestClient{
			lastUsed:   time.Now().UTC(),
			lastErr:    fmt.Errorf("fake error"),
			lastErrOcc: time.Now().UTC(),
		}
		two := &requestClient{}
		client, err := newClient(nil, Config{}, one, two)
		require.NoError(t, err)

		clients := client.sortClients()

		assert.Equal(t, two, clients[0])
	})

	t.Run("Picks second requester when first has been used", func(t *testing.T) {
		one := &requestClient{
			lastUsed: time.Now().UTC(),
		}
		two := &requestClient{}
		client, err := newClient(nil, Config{}, one, two)
		require.NoError(t, err)

		clients := client.sortClients()

		assert.Equal(t, two, clients[0])
	})

	t.Run("Picks second requester when it's the oldest", func(t *testing.T) {
		one := &requestClient{
			lastUsed: time.Now().UTC().Add(-time.Minute),
		}
		two := &requestClient{
			lastUsed: time.Now().UTC().Add(-3 * time.Minute),
		}
		three := &requestClient{
			lastUsed: time.Now().UTC().Add(-2 * time.Minute),
		}
		client, err := newClient(nil, Config{}, one, two, three)
		require.NoError(t, err)

		clients := client.sortClients()

		assert.Equal(t, two, clients[0])
	})

	t.Run("Picks third requester when second has error and first is last used", func(t *testing.T) {
		one := &requestClient{
			lastUsed: time.Now().UTC().Add(-time.Minute),
		}
		two := &requestClient{
			lastUsed:   time.Now().UTC().Add(-3 * time.Minute),
			lastErr:    fmt.Errorf("fake error"),
			lastErrOcc: time.Now().Add(-time.Minute),
		}
		three := &requestClient{
			lastUsed: time.Now().UTC().Add(-2 * time.Minute),
		}
		client := &Client{clients: []*requestClient{one, two, three}}

		clients := client.sortClients()

		assert.Equal(t, three, clients[0])
	})

	t.Run("Picks second requester when its oldest and all have old errors", func(t *testing.T) {
		one := &requestClient{
			lastUsed:   time.Now().UTC().Add(-time.Minute),
			lastErr:    fmt.Errorf("fake error"),
			lastErrOcc: time.Now().Add(-time.Minute),
		}
		two := &requestClient{
			lastUsed:   time.Now().UTC().Add(-3 * time.Minute),
			lastErr:    fmt.Errorf("fake error"),
			lastErrOcc: time.Now().Add(-3 * time.Minute),
		}
		three := &requestClient{
			lastUsed:   time.Now().UTC().Add(-2 * time.Minute),
			lastErr:    fmt.Errorf("fake error"),
			lastErrOcc: time.Now().Add(-2 * time.Minute),
		}
		client, err := newClient(nil, Config{}, one, two, three)
		require.NoError(t, err)

		clients := client.sortClients()

		assert.Equal(t, two, clients[0])
	})
}

func withServer(m func(t *testing.T) *http.ServeMux, test func(t *testing.T, host string)) func(t *testing.T) {
	return func(t *testing.T) {
		s := httptest.NewServer(m(t))
		defer s.Close()
		test(t, s.Listener.Addr().String())
	}
}

type debugStack struct {
	sync.Mutex
	messages []string
}

func (d *debugStack) Debug(args ...interface{}) {
	d.Lock()
	defer d.Unlock()

	// This should not happen in testing.
	m, ok := args[0].(string)
	if !ok {
		panic("could not convert message to string ")
	}

	d.messages = append(d.messages, m)
}
