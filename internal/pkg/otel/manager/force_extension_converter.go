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
	name string
}

func (fe *forceExtension) Convert(ctx context.Context, conf *confmap.Conf) error {
	err := func() error {
		err := conf.Merge(confmap.NewFromStringMap(map[string]interface{}{
			"extensions": map[string]interface{}{
				fe.name: nil,
			},
		}))
		if err != nil {
			return fmt.Errorf("merge into extensions failed: %w", err)
		}
		serviceConf, err := conf.Sub("service")
		if err != nil {
			//nolint:nilerr // ignore the error, no service defined in the configuration
			// this is going to error by the collector any way no reason to pollute with more
			// error information that is not really related to the issue at the moment
			return nil
		}
		extensionsRaw := serviceConf.Get("extensions")
		if extensionsRaw == nil {
			// no extensions defined on service (easily add it)
			err = conf.Merge(confmap.NewFromStringMap(map[string]interface{}{
				"service": map[string]interface{}{
					"extensions": []interface{}{fe.name},
				},
			}))
			if err != nil {
				return fmt.Errorf("merge into service::extensions failed: %w", err)
			}
			return nil
		}
		extensionsSlice, ok := extensionsRaw.([]interface{})
		if !ok {
			return fmt.Errorf("merge into service::extensions failed: expected []interface{}, got %T", extensionsRaw)
		}
		for _, extensionRaw := range extensionsSlice {
			extension, ok := extensionRaw.(string)
			if ok && extension == fe.name {
				// already present, nothing to do
				return nil
			}
		}
		extensionsSlice = append(extensionsSlice, fe.name)
		err = conf.Merge(confmap.NewFromStringMap(map[string]interface{}{
			"service": map[string]interface{}{
				"extensions": extensionsSlice,
			},
		}))
		if err != nil {
			return fmt.Errorf("merge into service::extensions failed: %w", err)
		}
		return nil
	}()
	if err != nil {
		return fmt.Errorf("failed to force enable %s extension: %w", fe.name, err)
	}
	return nil
}

func NewForceExtensionConverterFactory(name string) confmap.ConverterFactory {
	return confmap.NewConverterFactory(func(_ confmap.ConverterSettings) confmap.Converter {
		return &forceExtension{name}
	})
}
