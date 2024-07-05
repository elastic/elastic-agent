// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package application

import (
	"os"
	"strings"

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
	return func(comps []component.Component, _ map[string]interface{}) ([]component.Component, error) {
		for i, comp := range comps {
			if comp.InputSpec != nil && comp.InputSpec.InputType == endpoint {
				for j, unit := range comp.Units {
					if unit.Type == client.UnitTypeOutput && unit.Config.Type == elasticsearch {
						unitCfgMap := unit.Config.Source.AsMap()
						injectProxyURL(unitCfgMap, nil) // TODO
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

// injectProxyURL will inject the a proxy_url into the passed map if there is no existing key and there is an appropriate proxy through defined as an env var.
//
// The 1st item of the passed hosts list is checked to see if it starts with https or http and the corresponding proxy var is used.
// Nothing is injected if the *_PROXY env var is empty, the map contains proxy_url: "", or the map has proxy_disable: true.
// If no hosts are passed, then the HTTPS_PROXY value is used over the HTTP_PROXY value if it's defined.
func injectProxyURL(m map[string]interface{}, hosts []string) {
	if m == nil {
		return
	}
	// return if m already has a proxy
	if _, ok := m["proxy_url"]; ok {
		return
	}
	// Check if proxy_disable is part of config and true
	disabled, disabledDefined := m["proxy_disable"]
	if disabledDefined {
		val, ok := disabled.(bool)
		if ok && val {
			return
		}
	}

	var proxyURL string
	// If hosts are specified, check the 1st to see if HTTPS or HTTP is used to determine proxy
	if len(hosts) > 0 {
		if strings.HasPrefix(hosts[0], "https://") {
			proxyURL = os.Getenv("HTTPS_PROXY")
		} else {
			proxyURL = os.Getenv("HTTP_PROXY")
		}
	} else {
		// Otherwise prefer HTTPS_PROXY over HTTP_PROXY
		proxyURL = os.Getenv("HTTPS_PROXY")
		if proxyURL == "" {
			proxyURL = os.Getenv("HTTP_PROXY")
		}
	}
	// No proxy defined
	if proxyURL == "" {
		return
	}
	m["proxy_url"] = proxyURL
}
