// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build !define && !local

package define

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"
	"testing"

	"github.com/elastic/elastic-agent-libs/kibana"
	"github.com/elastic/elastic-agent/version"
	"github.com/elastic/go-elasticsearch/v8"
)

func defineAction(t *testing.T, req Requirements) *Info {
	// always validate requirement is valid
	if err := req.Validate(); err != nil {
		panic(fmt.Sprintf("test %s has invalid requirements: %s", t.Name(), err))
	}
	info := &Info{
		Namespace: getNamespace(t),
	}
	if req.Cloud != nil {
		info.ESClient = getESClient()
		info.KibanaClient = getKibanaClient()
	}
	return info
}

// getNamespace is a general namespace that the test can use that will ensure that it
// is unique and won't collide with other tests (even the same test from a different batch).
//
// this function uses a sha256 of the prefix, package and test name, to ensure that the
// length of the namespace is not over the 100 byte limit from Fleet
// see: https://www.elastic.co/guide/en/fleet/current/data-streams.html#data-streams-naming-scheme
func getNamespace(t *testing.T) string {
	prefix := os.Getenv("TEST_DEFINE_PREFIX")
	if prefix == "" {
		panic("TEST_DEFINE_PREFIX must be defined by the test runner")
	}
	name := fmt.Sprintf("%s-%s", prefix, t.Name())
	hasher := sha256.New()
	hasher.Write([]byte(name))
	return base64.URLEncoding.EncodeToString(hasher.Sum(nil))
}

// getESClient creates the elasticsearch client from the information passed from the test runner.
func getESClient() *elasticsearch.Client {
	esHost := os.Getenv("ELASTICSEARCH_HOST")
	esUser := os.Getenv("ELASTICSEARCH_USERNAME")
	esPass := os.Getenv("ELASTICSEARCH_PASSWORD")
	if esHost == "" || esUser == "" || esPass == "" {
		panic("ELASTICSEARCH_* must be defined by the test runner")
	}
	c, err := elasticsearch.NewClient(elasticsearch.Config{
		Addresses: []string{esHost},
		Username:  esUser,
		Password:  esPass,
	})
	if err != nil {
		panic(fmt.Errorf("failed to create elasticsearch client: %w", err))
	}
	return c
}

// getKibanaClient creates the kibana client from the information passed from the test runner.
func getKibanaClient() *kibana.Client {
	kibanaHost := os.Getenv("KIBANA_HOST")
	kibanaUser := os.Getenv("KIBANA_USERNAME")
	kibanaPass := os.Getenv("KIBANA_PASSWORD")
	if kibanaHost == "" || kibanaUser == "" || kibanaPass == "" {
		panic("KIBANA_* must be defined by the test runner")
	}
	c, err := kibana.NewClientWithConfigDefault(&kibana.ClientConfig{
		Host:          kibanaHost,
		Username:      kibanaUser,
		Password:      kibanaPass,
		IgnoreVersion: true,
	}, 0, "Elastic-Agent-Test-Define", version.GetDefaultVersion(), version.Commit(), version.BuildTime().String())
	if err != nil {
		panic(fmt.Errorf("failed to create kibana client: %w", err))
	}
	return c
}
