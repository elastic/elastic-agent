// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package agentprovider

import (
	"bytes"
	"context"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/confmap"
)

func TestBufferProvider_NewFactory(t *testing.T) {
	p, err := NewBufferProvider(nil)
	require.NoError(t, err)
	assert.Equal(t, p, p.NewFactory().Create(confmap.ProviderSettings{}))
}

func TestBufferProvider_Schema(t *testing.T) {
	p, err := NewBufferProvider(nil)
	require.NoError(t, err)
	assert.Equal(t, AgentConfigProviderSchemeName, p.Scheme())
}

func TestBufferProvider_URI(t *testing.T) {
	p, err := NewBufferProvider(nil)
	require.NoError(t, err)
	assert.Equal(t, p.uri, p.URI())
}

func TestBufferProvider_Retrieve(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := confmap.New()
	confMap := cfg.ToStringMap()
	confBytes, err := yaml.Marshal(confMap)
	require.NoError(t, err)

	p, err := NewBufferProvider(bytes.NewReader(confBytes))
	require.NoError(t, err)
	ret, err := p.Retrieve(ctx, p.URI(), func(event *confmap.ChangeEvent) {})
	require.NoError(t, err)
	retCfg, err := ret.AsConf()
	require.NoError(t, err)
	require.Equal(t, cfg, retCfg)
}

func TestBufferProvider_Shutdown(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := confmap.New()
	confMap := cfg.ToStringMap()
	confBytes, err := yaml.Marshal(confMap)
	require.NoError(t, err)

	p, err := NewBufferProvider(bytes.NewReader(confBytes))
	require.NoError(t, err)
	ret, err := p.Retrieve(ctx, p.URI(), func(event *confmap.ChangeEvent) {})
	require.NoError(t, err)
	retCfg, err := ret.AsConf()
	require.NoError(t, err)
	require.Equal(t, cfg, retCfg)

	err = p.Shutdown(ctx)
	require.NoError(t, err)
}
