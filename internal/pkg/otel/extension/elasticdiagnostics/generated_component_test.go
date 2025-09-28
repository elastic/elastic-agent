// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package elasticdiagnostics

import (
	"context"
	"fmt"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/component/componenttest"
	"go.opentelemetry.io/collector/confmap/confmaptest"
	"go.opentelemetry.io/collector/extension/extensiontest"
)

var typ = component.MustNewType("elastic_diagnostics")

func TestComponentFactoryType(t *testing.T) {
	require.Equal(t, typ, NewFactory().Type())
}

func TestComponentConfigStruct(t *testing.T) {
	require.NoError(t, componenttest.CheckConfigStruct(NewFactory().CreateDefaultConfig()))
}

func TestComponentLifecycle(t *testing.T) {
	factory := NewFactory()

	cm, err := confmaptest.LoadConf("metadata.yaml")
	require.NoError(t, err)
	cfg := factory.CreateDefaultConfig().(*Config)
	sub, err := cm.Sub("tests::config")
	require.NoError(t, err)
	require.NoError(t, sub.Unmarshal(&cfg))
	if runtime.GOOS == "windows" {
		// Use a different endpoint on Windows as /tmp/test.sock is not valid
		cfg.Endpoint = fmt.Sprintf("npipe://%s", cfg.Endpoint)
	}
	t.Run("shutdown", func(t *testing.T) {
		e, err := factory.Create(context.Background(), extensiontest.NewNopSettings(typ), cfg)
		require.NoError(t, err)
		err = e.Shutdown(context.Background())
		require.NoError(t, err)
	})
	t.Run("lifecycle", func(t *testing.T) {
		require.EventuallyWithT(t, func(collect *assert.CollectT) {
			firstExt, err := factory.Create(context.Background(), extensiontest.NewNopSettings(typ), cfg)
			require.NoError(collect, err)
			require.NoError(collect, firstExt.Start(context.Background(), newMdatagenNopHost()))
			require.NoError(collect, firstExt.Shutdown(context.Background()))
		}, 5*time.Second, 100*time.Millisecond)

		require.EventuallyWithT(t, func(collect *assert.CollectT) {
			secondExt, err := factory.Create(context.Background(), extensiontest.NewNopSettings(typ), cfg)
			require.NoError(collect, err)
			require.NoError(collect, secondExt.Start(context.Background(), newMdatagenNopHost()))
			require.NoError(collect, secondExt.Shutdown(context.Background()))
		}, 5*time.Second, 100*time.Millisecond)
	})
	t.Run("shutdown twice", func(t *testing.T) {
		require.EventuallyWithT(t, func(collect *assert.CollectT) {
			firstExt, err := factory.Create(context.Background(), extensiontest.NewNopSettings(typ), cfg)
			require.NoError(collect, err)
			require.NoError(collect, firstExt.Start(context.Background(), newMdatagenNopHost()))
			require.NoError(collect, firstExt.Shutdown(context.Background()))
			require.NoError(collect, firstExt.Shutdown(context.Background()))
		}, 5*time.Second, 100*time.Millisecond)
	})
	t.Run("shutdown twice - without start", func(t *testing.T) {
		firstExt, err := factory.Create(context.Background(), extensiontest.NewNopSettings(typ), cfg)
		require.NoError(t, err)
		require.NoError(t, firstExt.Shutdown(context.Background()))
		require.NoError(t, firstExt.Shutdown(context.Background()))
	})
}

var _ component.Host = (*mdatagenNopHost)(nil)

type mdatagenNopHost struct{}

func newMdatagenNopHost() component.Host {
	return &mdatagenNopHost{}
}

func (mnh *mdatagenNopHost) GetExtensions() map[component.ID]component.Component {
	return nil
}

func (mnh *mdatagenNopHost) GetFactory(_ component.Kind, _ component.Type) component.Factory {
	return nil
}
