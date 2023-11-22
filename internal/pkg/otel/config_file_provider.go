// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package otel

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"go.opentelemetry.io/collector/confmap"

	"github.com/elastic/elastic-agent/internal/pkg/config"
)

const schemeName = "file"

type provider struct{}

func NewFileProviderWithDefaults() confmap.Provider {
	return &provider{}
}

func (fmp *provider) Retrieve(_ context.Context, uri string, _ confmap.WatcherFunc) (*confmap.Retrieved, error) {
	if !strings.HasPrefix(uri, schemeName+":") {
		return nil, fmt.Errorf("%q uri is not supported by %q provider", uri, schemeName)
	}

	// Clean the path before using it.
	content, err := os.ReadFile(filepath.Clean(uri[len(schemeName)+1:]))
	if err != nil {
		return nil, fmt.Errorf("unable to read the file %v: %w", uri, err)
	}

	config, err := config.NewConfigFrom(content)
	if err != nil {
		return nil, err
	}

	rawConf := defaultOtelConfig()
	if err := config.Unpack(rawConf); err != nil {
		return nil, err
	}
	return confmap.NewRetrieved(rawConf)
}

func (*provider) Scheme() string {
	return schemeName
}

func (*provider) Shutdown(context.Context) error {
	return nil
}

func defaultOtelConfig() map[string]any {
	defaultConfig := map[string]any{
		"service": map[string]any{
			"telemetry": map[string]any{
				"logs": map[string]any{
					"output_paths": []string{"stdout"},
				},
			},
		},
	}

	return defaultConfig
}
