// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package agentprovider

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/confmap"
)

func TestProvider_NewFactory(t *testing.T) {
	p := NewProvider(nil)
	assert.Equal(t, p, p.NewFactory().Create(confmap.ProviderSettings{}))
}

func TestProvider_Schema(t *testing.T) {
	p := NewProvider(nil)
	assert.Equal(t, schemeName, p.Scheme())
}

func TestProvider_URI(t *testing.T) {
	p := NewProvider(nil)
	assert.Equal(t, p.uri, p.URI())
}

func TestProvider_Update(t *testing.T) {
	cfg := confmap.New()
	cfg2 := confmap.New()
	cfg3 := confmap.New()

	p := NewProvider(cfg)
	p.Update(cfg2) // should not block
	p.Update(cfg3) // should not block
}

func TestProvider_Retrieve(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := confmap.New()

	p := NewProvider(cfg)
	ret, err := p.Retrieve(ctx, p.URI(), func(event *confmap.ChangeEvent) {})
	require.NoError(t, err)
	retCfg, err := ret.AsConf()
	require.NoError(t, err)
	require.Equal(t, cfg, retCfg)
}

func TestProvider_Retrieve_Update(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := confmap.New()
	cfg2 := confmap.New()

	ch := make(chan *confmap.ChangeEvent, 1)

	p := NewProvider(cfg)
	ret, err := p.Retrieve(ctx, p.URI(), func(event *confmap.ChangeEvent) {
		ch <- event
	})
	require.NoError(t, err)
	retCfg, err := ret.AsConf()
	require.NoError(t, err)
	require.Equal(t, cfg, retCfg)

	p.Update(cfg2)
	evt := <-ch
	require.NotNil(t, evt)

	ret2, err := p.Retrieve(ctx, p.URI(), func(event *confmap.ChangeEvent) {})
	require.NoError(t, err)
	retCfg2, err := ret2.AsConf()
	require.NoError(t, err)
	assert.Equal(t, cfg2, retCfg2)
}

func TestProvider_Shutdown(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := confmap.New()

	p := NewProvider(cfg)
	ret, err := p.Retrieve(ctx, p.URI(), func(event *confmap.ChangeEvent) {})
	require.NoError(t, err)
	retCfg, err := ret.AsConf()
	require.NoError(t, err)
	require.Equal(t, cfg, retCfg)

	err = p.Shutdown(ctx)
	require.NoError(t, err)
}
