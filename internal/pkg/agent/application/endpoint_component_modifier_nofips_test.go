// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build !requirefips

package application

import (
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/pkg/core/logger/loggertest"
)

// TestEndpointComponentModifier_EndpointTLSComponentModifier_mTLS_passphrase tests encrypted private keys
// It was moved from endpoint_component_modifier_test.go TestEndpointComponentModifier
// TODO: Move back once FIPS distributions support encryped private keys
func TestEndpointComponentModifier_EndpointTLSComponentModifier_mTLS_passphrase(t *testing.T) {
	log, obs := loggertest.New("TestEndpointComponentModifier_EndpointTLSComponentModifier_mTLS_passphrase")
	defer func() {
		if !t.Failed() {
			return
		}

		loggertest.PrintObservedLogs(obs.TakeAll(), t.Log)
	}()
	pair, certPath, certKeyPath, certKeyPassPath := prepareEncTLSCertificates(t)
	compModifier := EndpointTLSComponentModifier(log)
	comps, err := compModifier(makeComponent(t, fmt.Sprintf(`{
		"fleet": {
		  "ssl": {
		    "certificate": %q,
		    "key": %q,
		    "key_passphrase_path": %q
		  }
		}}`, certPath, certKeyPath, certKeyPassPath)),
		map[string]interface{}{
			"fleet": map[string]interface{}{
				"ssl": map[string]interface{}{
					"certificate":         certPath,
					"key":                 certKeyPath,
					"key_passphrase_path": certKeyPassPath,
				},
			},
		})
	require.NoError(t, err)
	compareComponents(t, comps, makeComponent(t, fmt.Sprintf(`{
			  "fleet": {
			    "ssl": {
			      "certificate": %q,
			      "key": %q
			    }
			  }
			}`, pair.Cert, pair.Key)))
}

// TestEndpointTLSComponentModifier_cache_miss tests encrypted private keys
// It was moved from endpoint_component_modifier_test.go
// TODO: Move back once FIPS distributions support encryped private keys
func TestEndpointTLSComponentModifier_cache_miss(t *testing.T) {
	log, obs := loggertest.New("TestEndpointSignedComponentModifier")
	defer func() {
		if !t.Failed() {
			return
		}

		loggertest.PrintObservedLogs(obs.TakeAll(), t.Log)
	}()

	cache := tlsCache{
		mu: &sync.Mutex{},

		CacheKey:    "/old-cache-key",
		Certificate: "cached certificate",
		Key:         "cached key",
	}
	pair, certPath, certKeyPath, certKeyPassPath := prepareEncTLSCertificates(t)
	cackeKey := cache.MakeKey(certKeyPassPath, certPath, certKeyPath)

	comps := makeComponent(t, fmt.Sprintf(`{
			  "fleet": {
			    "ssl": {
			      "certificate": %q,
			      "key": %q,
			      "key_passphrase_path": %q
			    }
			  }
			}`, certPath, certKeyPath, certKeyPassPath))
	cfg := map[string]interface{}{
		"fleet": map[string]interface{}{
			"ssl": map[string]interface{}{
				"certificate":         certPath,
				"key":                 certKeyPath,
				"key_passphrase_path": certKeyPassPath,
			},
		},
	}
	wantComps := makeComponent(t, fmt.Sprintf(`{
			  "fleet": {
			    "ssl": {
			      "certificate": %q,
			      "key": %q
			    }
			  }
			}`, pair.Cert, pair.Key))

	modifier := newEndpointTLSComponentModifier(log, &cache)
	got, err := modifier(comps, cfg)
	require.NoError(t, err, "unexpected error")

	assert.Equal(t, cackeKey, cache.CacheKey, "passphrase path did not match")
	assert.Equal(t, string(pair.Cert), cache.Certificate, "certificate did not match")
	assert.Equal(t, string(pair.Key), cache.Key, "key did not match")

	compareComponents(t, got, wantComps)
}
