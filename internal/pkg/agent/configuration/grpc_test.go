// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package configuration

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGRPCAddr(t *testing.T) {
	testcases := []struct {
		name     string
		addr     string
		port     uint16
		expected string
	}{{
		name:     "ipv4",
		addr:     "127.0.0.1",
		expected: "127.0.0.1:0",
	}, {
		name:     "ipv4+port",
		addr:     "127.0.0.1",
		port:     1,
		expected: "127.0.0.1:1",
	}, {
		name:     "ipv6",
		addr:     "::1",
		expected: "[::1]:0",
	}, {
		name:     "ipv6+port",
		addr:     "::1",
		port:     1,
		expected: "[::1]:1",
	}}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := GRPCConfig{
				Address: tc.addr,
				Port:    tc.port,
			}
			assert.Equal(t, tc.expected, cfg.String())
		})
	}
}
