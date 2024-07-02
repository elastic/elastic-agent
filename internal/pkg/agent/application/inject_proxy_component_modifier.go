// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package application

import (
	"os"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/coordinator"
	"github.com/elastic/elastic-agent/pkg/component"
)

// InjectProxyEndpointModifier injects a proxy_url value into endpoint's output config if one is not set.
//
// This will inject a proxy_url if there is no existing key and the agent has a proxy set through an environment variable.
// The URL used is the HTTPS_PROXY env var. If that's not set the HTTP_PROXY env var is used.
// If there are no env vars set, or the unit's config has `proxy_disable: true`, nothing is injected
// If the output config has `proxy_url: ""`, it will not be overwritten.
func InjectProxyEndpointModifier() coordinator.ComponentsModifier {
	proxyURL := os.Getenv("HTTPS_PROXY")
	if proxyURL == "" {
		proxyURL = os.Getenv("HTTP_PROXY")
	}
	return func(comps []component.Component, _ map[string]interface{}) ([]component.Component, error) {
		if proxyURL == "" {
			return comps, nil
		}
		for i, comp := range comps {
			if comp.InputSpec != nil && comp.InputSpec.InputType == endpoint {
				for j, unit := range comp.Units {
					if unit.Type == client.UnitTypeOutput && unit.Config.Type == elasticsearch {
						unitCfgMap := unit.Config.Source.AsMap()
						// Check if proxy_url is part of config
						if _, ok := unitCfgMap["proxy_url"]; ok {
							continue
						}

						// Check if proxy_disable is part of config and true
						disabled, disabledDefined := unitCfgMap["proxy_disable"]
						if disabledDefined {
							val, ok := disabled.(bool)
							if ok && val {
								continue
							}
						}
						unitCfgMap["proxy_url"] = proxyURL
						unitCfg, err := component.ExpectedConfig(unitCfgMap)
						if err != nil {
							return nil, err
						}
						unit.Config = unitCfg
					}
					comp.Units[j] = unit
				}
			}
			comps[i] = comp
		}
		return comps, nil
	}
}
