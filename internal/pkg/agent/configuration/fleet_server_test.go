// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package configuration

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/elastic/elastic-agent-libs/transport/tlscommon"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
)

func TestElasticsearchFromConnStr(t *testing.T) {
	testcases := []struct {
		name     string
		conn     string
		token    string
		path     string
		insecure bool
		es       Elasticsearch
		err      error
	}{{
		name:     "ok",
		conn:     "https://localhost:9200",
		token:    "my-token",
		path:     "",
		insecure: false,
		es: Elasticsearch{
			Protocol:     "https",
			Hosts:        []string{"localhost:9200"},
			ServiceToken: "my-token",
		},
		err: nil,
	}, {
		name:     "ok with path",
		conn:     "https://localhost:9200",
		token:    "",
		path:     "/path/to/token",
		insecure: false,
		es: Elasticsearch{
			Protocol:         "https",
			Hosts:            []string{"localhost:9200"},
			ServiceTokenPath: "/path/to/token",
		},
		err: nil,
	}, {
		name:     "no token or path",
		conn:     "https://localhost:9200",
		token:    "",
		path:     "",
		insecure: false,
		es:       Elasticsearch{},
		err:      errors.New("invalid connection string: must include a service token"),
	}, {
		name:     "http connection",
		conn:     "http://localhost:9200",
		token:    "my-token",
		path:     "",
		insecure: false,
		es: Elasticsearch{
			Protocol:     "http",
			Hosts:        []string{"localhost:9200"},
			ServiceToken: "my-token",
		},
		err: nil,
	}, {
		name:     "insecure https",
		conn:     "https://localhost:9200",
		token:    "my-token",
		path:     "",
		insecure: true,
		es: Elasticsearch{
			Protocol:     "https",
			Hosts:        []string{"localhost:9200"},
			ServiceToken: "my-token",
			TLS: &tlscommon.Config{
				VerificationMode: tlscommon.VerifyNone,
			},
		},
		err: nil,
	}, {
		name:     "file schema",
		conn:     "file:///path/to/socket",
		token:    "my-token",
		path:     "",
		insecure: false,
		es:       Elasticsearch{},
		err:      errors.New("invalid connection string: scheme must be http or https"),
	}, {
		name:     "bad conn string",
		conn:     "http://local host",
		token:    "my-token",
		path:     "",
		insecure: false,
		es:       Elasticsearch{},
		err:      errors.New("parse \"http://local host\": invalid character \" \" in host name"),
	}}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			es, err := ElasticsearchFromConnStr(tc.conn, tc.token, tc.path, tc.insecure)
			if tc.err != nil {
				assert.EqualError(t, err, tc.err.Error())
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, tc.es, es)
		})
	}
}
