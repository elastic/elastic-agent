// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package manager

import (
	"context"
	"fmt"

	"go.opentelemetry.io/collector/confmap"
)

// forceExtension is a Converter that forces that an extension is enabled in the OTel configuration.
type forceExtension struct {
	name   string
	config map[string]any
}

func (fe *forceExtension) Convert(_ context.Context, conf *confmap.Conf) error {
	if conf.IsSet("extensions::" + fe.name) {
		// already defined by the user, nothing to do
		return nil
	}
	err := mergeWithExtensions(conf, confmap.NewFromStringMap(map[string]interface{}{
		"extensions": map[string]interface{}{
			fe.name: fe.config,
		},
		"service": map[string]interface{}{
			"extensions": []interface{}{fe.name},
		},
	}))
	if err != nil {
		return fmt.Errorf("failed to force enable %s extension: %w", fe.name, err)
	}
	return nil
}

func NewForceExtensionConverterFactory(name string, config map[string]any) confmap.ConverterFactory {
	return confmap.NewConverterFactory(func(_ confmap.ConverterSettings) confmap.Converter {
		return &forceExtension{name, config}
	})
}
