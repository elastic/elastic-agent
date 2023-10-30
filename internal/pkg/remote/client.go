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

	"github.com/hashicorp/go-multierror"

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

func (r *requestClient) SetLastError(err error) {
	r.lastUsed = time.Now().UTC()
	r.lastErr = err
	if err != nil {
		r.lastErrOcc = r.lastUsed
	} else {
		r.lastErrOcc = time.Time{}
	}
}

// Client wraps a http.Client and takes care of making the raw calls, the client should
// stay simple and specifics should be implemented in external action instead of adding new methods
// to the client. For authenticated calls or sending fields on every request, create a custom RoundTripper
// implementation that will take care of the boilerplate.
type Client struct {
	log        *logger.Logger
	clientLock sync.Mutex
	clients    []*requestClient
	config     Config
}

// NewConfigFromURL returns a Config based on a received host.
func NewConfigFromURL(URL string) (Config, error) {
	u, err := url.Parse(URL)
	if err != nil {
		return Config{}, fmt.Errorf("could not parse url: %w", err)
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
		return nil, fmt.Errorf("invalidate configuration: %w", err)
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
		"creating remote client with %d hosts", hostCount)
	clients := make([]*requestClient, hostCount)
	for i, host := range hosts {
		baseURL, err := urlutil.MakeURL(string(cfg.Protocol), p, host, 0)
		if err != nil {
			return nil, fmt.Errorf("invalid fleet-server endpoint: %w", err)
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
				return nil, fmt.Errorf("fail to create transport client: %w", err)
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

	return newClient(log, cfg, clients...)
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

	var resp *http.Response
	var multiErr error

	clients := c.sortClients()

	for i, requester := range clients {
		req, err := requester.newRequest(method, path, params, body)
		if err != nil {
			return nil, fmt.Errorf(
				"fail to create HTTP request using method %s to %s: %w",
				method, path, err)
		}
		c.log.Debugf("Creating new request to request URL %s", req.URL.String())

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

		resp, err = requester.client.Do(req.WithContext(ctx))

		// Using the same lock that was used for sorting above
		c.clientLock.Lock()
		requester.SetLastError(err)
		c.clientLock.Unlock()

		if err != nil {
			msg := fmt.Sprintf("requester %d/%d to host %s errored",
				i, len(clients), requester.host)
			multiErr = multierror.Append(multiErr, fmt.Errorf("%s: %w", msg, err))

			// Using debug level as the error is only relevant if all clients fail.
			c.log.With("error", err).Debugf(msg)
			continue
		}
		c.checkApiVersionHeaders(reqID, resp)

		return resp, nil
	}

	return nil, fmt.Errorf("all hosts failed: %w", multiErr)
}

func (c *Client) checkApiVersionHeaders(reqID string, resp *http.Response) {
	const elasticApiVersionHeaderKey = "Elastic-Api-Version"
	const warningHeaderKey = "Warning"

	warning := resp.Header.Get(warningHeaderKey)
	if warning != "" {
		c.log.With("http.request.id", reqID).Warnf("warning in fleet response: %q", warning)
	}

	if downgradeVersion := resp.Header.Get(elasticApiVersionHeaderKey); resp.StatusCode == http.StatusBadRequest && downgradeVersion != "" {
		// fleet server requested a downgrade to a different api version, we should bubble up an error until some kind
		// of fallback mechanism can instantiate the requested version. This is not yet implemented so we log an error
		c.log.With("http.request.id", reqID).Errorf("fleet requested a different api version %q but this is currently not implemented", downgradeVersion)
	}
}

// URI returns the remote URI.
func (c *Client) URI() string {
	host := c.config.GetHosts()[0]
	if strings.HasPrefix(host, string(ProtocolHTTPS)+"://") ||
		strings.HasPrefix(host, string(ProtocolHTTP)+"://") {
		return host + "/" + c.config.Path
	}
	return string(c.config.Protocol) + "://" + host + "/" + c.config.Path
}

// newClient creates a new API client.
func newClient(
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

// sortClients sort the clients according to the following priority:
//   - never used
//   - without errors, last used first when more than one does not have errors
//   - last errored.
//
// It also removes the last error after retryOnBadConnTimeout has elapsed.
func (c *Client) sortClients() []*requestClient {
	c.clientLock.Lock()
	defer c.clientLock.Unlock()

	now := time.Now().UTC()

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

		// Lastly, the one that errored last
		return c.clients[i].lastUsed.Before(c.clients[j].lastUsed)
	})

	// return a copy of the slice so we can iterate over it without the lock
	res := make([]*requestClient, len(c.clients))
	copy(res, c.clients)
	return res
}

func (r requestClient) newRequest(method string, path string, params url.Values, body io.Reader) (*http.Request, error) {
	path = strings.TrimPrefix(path, "/")
	newPath := strings.Join([]string{r.host, path, "?", params.Encode()}, "")

	return http.NewRequestWithContext(context.TODO(), method, newPath, body)
}
