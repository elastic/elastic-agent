// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package workflowrunner

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/elastic/elastic-agent-libs/config"
	"github.com/elastic/elastic-agent-libs/transport/httpcommon"
	"github.com/elastic/go-elasticsearch/v8"
)

const outputTypeElasticsearch = "elasticsearch"

// Indexer stores a result document under the given id.
type Indexer interface {
	Index(ctx context.Context, index, id string, doc any) error
}

// esOutputConfig is the subset of the agent's elasticsearch output settings the runner uses.
type esOutputConfig struct {
	Type     string            `config:"type"`
	Hosts    []string          `config:"hosts"`
	Protocol string            `config:"protocol"`
	Path     string            `config:"path"`
	APIKey   string            `config:"api_key"`
	Username string            `config:"username"`
	Password string            `config:"password"`
	Headers  map[string]string `config:"headers"`

	Transport httpcommon.HTTPTransportSettings `config:",inline"`
}

type esIndexer struct {
	client *elasticsearch.Client
}

// newESIndexer builds an Indexer from the output unit's config source.
func newESIndexer(source map[string]interface{}) (Indexer, error) {
	raw, err := config.NewConfigFrom(source)
	if err != nil {
		return nil, fmt.Errorf("reading output config: %w", err)
	}
	cfg := esOutputConfig{Transport: httpcommon.DefaultHTTPTransportSettings()}
	if err := raw.Unpack(&cfg); err != nil {
		return nil, fmt.Errorf("unpacking output config: %w", err)
	}
	if cfg.Type != outputTypeElasticsearch {
		return nil, fmt.Errorf("unsupported output type %q; only %q is supported", cfg.Type, outputTypeElasticsearch)
	}
	if len(cfg.Hosts) == 0 {
		return nil, errors.New("output has no hosts")
	}

	rt, err := cfg.Transport.RoundTripper()
	if err != nil {
		return nil, fmt.Errorf("building output transport: %w", err)
	}

	header := http.Header{}
	for k, v := range cfg.Headers {
		header.Set(k, v)
	}
	esCfg := elasticsearch.Config{
		Addresses: hostURLs(cfg.Hosts, cfg.Protocol, cfg.Path),
		Username:  cfg.Username,
		Password:  cfg.Password,
		APIKey:    encodeAPIKey(cfg.APIKey),
		Header:    header,
		Transport: rt,
	}
	client, err := elasticsearch.NewClient(esCfg)
	if err != nil {
		return nil, fmt.Errorf("creating elasticsearch client: %w", err)
	}
	return &esIndexer{client: client}, nil
}

// hostURLs applies the output's protocol and path to hosts given without a scheme,
// matching how Beats interpret the elasticsearch output.
func hostURLs(hosts []string, protocol, path string) []string {
	if protocol == "" {
		protocol = "http"
	}
	path = strings.Trim(path, "/")
	out := make([]string, 0, len(hosts))
	for _, h := range hosts {
		u := h
		if !strings.Contains(u, "://") {
			u = protocol + "://" + u
		}
		if path != "" {
			u = strings.TrimRight(u, "/") + "/" + path
		}
		out = append(out, u)
	}
	return out
}

// encodeAPIKey accepts the output's api_key in the "id:key" form Fleet and
// standalone policies use and returns the base64 form Elasticsearch expects.
func encodeAPIKey(key string) string {
	if key == "" || !strings.Contains(key, ":") {
		return key
	}
	return base64.StdEncoding.EncodeToString([]byte(key))
}

func (e *esIndexer) Index(ctx context.Context, index, id string, doc any) error {
	body, err := json.Marshal(doc)
	if err != nil {
		return fmt.Errorf("encoding result document: %w", err)
	}
	resp, err := e.client.Index(
		index,
		bytes.NewReader(body),
		e.client.Index.WithContext(ctx),
		e.client.Index.WithDocumentID(id),
		e.client.Index.WithOpType("create"),
		e.client.Index.WithRefresh("wait_for"),
	)
	if err != nil {
		return fmt.Errorf("indexing result document: %w", err)
	}
	defer resp.Body.Close()
	// 409 means a previous delivery of this action already stored its result.
	if resp.StatusCode == http.StatusConflict {
		return nil
	}
	if resp.IsError() {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("indexing result document: %s: %s", resp.Status(), bytes.TrimSpace(msg))
	}
	return nil
}
