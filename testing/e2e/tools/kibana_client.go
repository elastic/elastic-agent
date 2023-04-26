package tools

import (
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"

	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	"go.elastic.co/apm"
)

// Client is responsible for exporting dashboards from Kibana.
type Client struct {
	clusterConfig ClusterConfig
}

// HTTPHeader representation of a key-value pair to be passed as a HTTP header
type HTTPHeader struct {
	key   string
	value string
}

// NewClient creates a new instance of the client.
func NewClient(clusterConfig *ClusterConfig) (*Client, error) {
	return &Client{
		clusterConfig: *clusterConfig,
	}, nil
}

func (c *Client) get(ctx context.Context, resourcePath string, headers ...HTTPHeader) (int, []byte, error) {
	return c.sendRequest(ctx, http.MethodGet, resourcePath, nil, headers...)
}

func (c *Client) post(ctx context.Context, resourcePath string, body []byte, headers ...HTTPHeader) (int, []byte, error) {
	return c.sendRequest(ctx, http.MethodPost, resourcePath, body, headers...)
}

func (c *Client) sendRequest(ctx context.Context, method, resourcePath string, body []byte, headers ...HTTPHeader) (int, []byte, error) {
	span, _ := apm.StartSpanOptions(ctx, "Sending HTTP request", "http.request."+method, apm.SpanOptions{
		Parent: apm.SpanFromContext(ctx).TraceContext(),
	})
	span.Context.SetLabel("method", method)
	span.Context.SetLabel("base", c.clusterConfig.KibanaConfig.Host)
	span.Context.SetLabel("resourcePath", resourcePath)
	defer span.End()

	reqBody := bytes.NewReader(body)
	base, err := url.Parse(c.clusterConfig.KibanaConfig.Host)
	if err != nil {
		return 0, nil, fmt.Errorf("could not create base URL from host: %v. %w", c.clusterConfig.KibanaConfig.Host, err)
	}

	rel, err := url.Parse(resourcePath)
	if err != nil {
		return 0, nil, fmt.Errorf("could not create relative URL from resource path: %v. %w", resourcePath, err)
	}

	u := base.ResolveReference(rel)

	log.WithFields(log.Fields{
		"method":  method,
		"url":     u,
		"body":    body,
		"headers": headers,
	}).Trace("Kibana API Query")

	req, err := http.NewRequestWithContext(ctx, method, u.String(), reqBody)
	if err != nil {
		return 0, nil, fmt.Errorf("could not create %v request to Kibana API resource: %s. %w", method, resourcePath, err)
	}

	req.SetBasicAuth(c.clusterConfig.KibanaConfig.User, c.clusterConfig.KibanaConfig.Password)
	req.Header.Add("content-type", "application/json")
	req.Header.Add("kbn-xsrf", fmt.Sprintf("e2e-tests-%s", uuid.New().String()))

	for _, header := range headers {
		req.Header.Add(header.key, header.value)
	}

	client := http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("could not send request to Kibana API. %w", err)
	}

	defer resp.Body.Close()
	body, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, nil, fmt.Errorf("could not read response body. %w", err)
	}

	return resp.StatusCode, body, nil
}
