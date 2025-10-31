// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package application

import (
	"os"
	"strconv"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/coordinator"
	"github.com/elastic/elastic-agent/internal/pkg/otel/translate"
	"github.com/elastic/elastic-agent/pkg/component"
)

// EnableBeatsReceivers creates a component modifier that enables beats receivers
// for supported input types when the ENABLE_BEATS_RECEIVERS environment variable is set.
func EnableBeatsReceivers() coordinator.ComponentsModifier {
	enabled, _ := strconv.ParseBool(envWithDefault("false", "ENABLE_BEATS_RECEIVERS"))

	return func(comps []component.Component, cfg map[string]interface{}) ([]component.Component, error) {
		if !enabled {
			return comps, nil
		}

		for i, comp := range comps {
			if err := translate.VerifyComponentIsOtelSupported(&comp); err != nil {
				continue
			}

			comp.RuntimeManager = component.OtelRuntimeManager
			comps[i] = comp
		}

		return comps, nil
	}
}

func envWithDefault(def string, keys ...string) string {
	for _, key := range keys {
		val, ok := os.LookupEnv(key)
		if ok {
			return val
		}
	}
	return def
}
