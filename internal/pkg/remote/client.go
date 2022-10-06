// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package remote

import (
	"context"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/pkg/errors"

	urlutil "github.com/elastic/elastic-agent-libs/kibana"
	"github.com/elastic/elastic-agent-libs/transport/httpcommon"

	"github.com/elastic/elastic-agent/internal/pkg/config"
	"github.com/elastic/elastic-agent/internal/pkg/id"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

const (
	retryOnBadConnTimeout = 5 * time.Minute
)

type wrapperFunc func(rt http.RoundTripper) (http.RoundTripper, error)

type requestClient struct {
	host       string
	client     http.Client
	lastUsed   time.Time
	lastErr    error
	lastErrOcc time.Time
}

// Client wraps a http.Client and takes care of making the raw calls, the client should
// stay simple and specifics should be implemented in external action instead of adding new methods
// to the client. For authenticated calls or sending fields on every request, create a custom RoundTripper
// implementation that will take care of the boiler plate.
type Client struct {
	log      *logger.Logger
	clientMu sync.Mutex
	clients  []*requestClient
	config   Config
}

// NewConfigFromURL returns a Config based on a received host.
func NewConfigFromURL(URL string) (Config, error) {
	u, err := url.Parse(URL)
	if err != nil {
		return Config{}, errors.Wrap(err, "could not parse url")
	}

	c := DefaultClientConfig()
	c.Protocol = Protocol(u.Scheme)
	c.Host = u.Host
	c.Path = u.Path

	return c, nil
}

// NewWithRawConfig returns a new client with a specified configuration.
func NewWithRawConfig(log *logger.Logger, config *config.Config, wrapper wrapperFunc) (*Client, error) {
	l := log
	if l == nil {
		log, err := logger.New("client", false)
		if err != nil {
			return nil, err
		}
		l = log
	}

	cfg := Config{}
	if err := config.Unpack(&cfg); err != nil {
		return nil, errors.Wrap(err, "invalidate configuration")
	}

	return NewWithConfig(l, cfg, wrapper)
}

// NewWithConfig takes a Config and return a client.
func NewWithConfig(log *logger.Logger, cfg Config, wrapper wrapperFunc) (*Client, error) {
	// Normalize the URL with the path any spaces configured.
	var p string
	if len(cfg.SpaceID) > 0 {
		p = strings.Join([]string{cfg.Path, cfg.SpaceID}, "/")
	} else {
		p = cfg.Path
	}

	if !strings.HasSuffix(p, "/") {
		p = p + "/"
	}

	hosts := cfg.GetHosts()
	hostCount := len(hosts)
	log.With("hosts", hosts).Debugf(
		"creating remote client with %d hosts", hostCount, hosts)
	clients := make([]*requestClient, hostCount)
	for i, host := range hosts {
		baseURL, err := urlutil.MakeURL(string(cfg.Protocol), p, host, 0)
		if err != nil {
			return nil, errors.Wrap(err, "invalid fleet-server endpoint")
		}

		transport, err := cfg.Transport.RoundTripper(
			httpcommon.WithAPMHTTPInstrumentation(),
			httpcommon.WithForceAttemptHTTP2(true),
		)
		if err != nil {
			return nil, err
		}

		if wrapper != nil {
			transport, err = wrapper(transport)
			if err != nil {
				return nil, errors.Wrap(err, "fail to create transport client")
			}
		}

		httpClient := http.Client{
			Transport: transport,
			Timeout:   cfg.Transport.Timeout,
		}

		clients[i] = &requestClient{
			host:   baseURL,
			client: httpClient,
		}
	}

	return new(log, cfg, clients...)
}

// Send executes a direct calls against the API, the method will take care of cloning and
// also adding the necessary headers likes: "Content-Type", "Accept", and "kbn-xsrf".
// No assumptions are done on the response concerning the received format, this will be the responsibility
// of the implementation to correctly unpack any received data.
//
// NOTE:
// - The caller of this method is free to override any value found in the headers.
// - The magic of unpacking of errors is not done in the Send method, a helper method is provided.
func (c *Client) Send(
	ctx context.Context,
	method, path string,
	params url.Values,
	headers http.Header,
	body io.Reader,
) (*http.Response, error) {
	// Generate a request ID for tracking
	var reqID string
	if u, err := id.Generate(); err == nil {
		reqID = u.String()
	}

	c.log.Debugf("Request method: %s, path: %s, reqID: %s", method, path, reqID)
	c.clientMu.Lock()
	defer c.clientMu.Unlock()

	var err error
	var req *http.Request
	var resp *http.Response

	c.sortClients()
	for i, requester := range c.clients {
		req, err = requester.newRequest(method, path, params, body)
		if err != nil {
			return nil, errors.Wrapf(err, "fail to create HTTP request using method %s to %s", method, path)
		}

		// Add generals headers to the request, we are dealing exclusively with JSON.
		// Content-Type / Accepted type can be overridden by the caller.
		req.Header.Set("Content-Type", "application/json")
		req.Header.Add("Accept", "application/json")
		// This header should be specific to fleet-server or remove it
		req.Header.Set("kbn-xsrf", "1") // Without this Kibana will refuse to answer the request.

		// If available, add the request id as an HTTP header
		if reqID != "" {
			req.Header.Add("X-Request-ID", reqID)
		}

		// copy headers.
		for header, values := range headers {
			for _, v := range values {
				req.Header.Add(header, v)
			}
		}

		requester.lastUsed = time.Now().UTC()

		resp, err = requester.client.Do(req.WithContext(ctx))
		if err != nil {
			requester.lastErr = err
			requester.lastErrOcc = time.Now().UTC()

			// Using debug level as the error is only relevant if all clients fail.
			c.log.With("error", err).Debugf("requester %d/%d to host %s errored",
				i, len(c.clients), requester.host)
			continue
		}

		requester.lastErr = nil
		requester.lastErrOcc = time.Time{}
		return resp, nil
	}

	return nil, fmt.Errorf("all hosts failed, last error: %w", err)
}

// URI returns the remote URI.
func (c *Client) URI() string {
	host := c.config.GetHosts()[0]
	return string(c.config.Protocol) + "://" + host + "/" + c.config.Path
}

// new creates new API client.
func new(
	log *logger.Logger,
	cfg Config,
	clients ...*requestClient,
) (*Client, error) {
	// Shuffle so all the agents don't access the hosts in the same order
	rand.Shuffle(len(clients), func(i, j int) {
		clients[i], clients[j] = clients[j], clients[i]
	})

	c := &Client{
		log:     log,
		clients: clients,
		config:  cfg,
	}
	return c, nil
}

// sortClients returns the requester to use.
//
// It excludes clients that have errored in the last 5 minutes.
func (c *Client) sortClients() {
	now := time.Now().UTC()

	// Less reports whether the element with index i
	// must sort before the element with index j.

	sort.Slice(c.clients, func(i, j int) bool {
		// First, set them good if the timout has elapsed
		if c.clients[i].lastErr != nil &&
			now.Sub(c.clients[i].lastErrOcc) > retryOnBadConnTimeout {
			c.clients[i].lastErr = nil
			c.clients[i].lastErrOcc = time.Time{}
		}
		if c.clients[j].lastErr != nil &&
			now.Sub(c.clients[j].lastErrOcc) > retryOnBadConnTimeout {
			c.clients[j].lastErr = nil
			c.clients[j].lastErrOcc = time.Time{}
		}

		// Pick not yet used first, but if both haven't been used yet,
		// we return false to comply with the sort.Interface definition.
		if c.clients[i].lastUsed.IsZero() &&
			c.clients[j].lastUsed.IsZero() {
			return false
		}

		// Pick not yet used first
		if c.clients[i].lastUsed.IsZero() {
			return true
		}

		// If none has errors, pick the last used
		// Then, the one without errors
		if c.clients[i].lastErr == nil &&
			c.clients[j].lastErr == nil {
			return c.clients[i].lastUsed.Before(c.clients[j].lastUsed)
		}

		// Then, the one without error
		if c.clients[i].lastErr == nil {
			return true
		}

		// Lastly, the one that errored first
		return c.clients[i].lastUsed.Before(c.clients[j].lastUsed)
	})
}

func (r requestClient) newRequest(method string, path string, params url.Values, body io.Reader) (*http.Request, error) {
	path = strings.TrimPrefix(path, "/")
	newPath := strings.Join([]string{r.host, path, "?", params.Encode()}, "")

	return http.NewRequest(method, newPath, body)
}
