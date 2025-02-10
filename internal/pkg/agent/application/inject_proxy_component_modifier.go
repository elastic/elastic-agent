// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package application

import (
	"net/http"

	"golang.org/x/net/http/httpproxy"

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

						// convert unitCfgMap["hosts"] to []string
						var hosts []string
						if hArr, ok := unitCfgMap["hosts"]; ok {
							if arr, ok := hArr.([]interface{}); ok {
								for _, v := range arr {
									host, ok := v.(string)
									if !ok {
										continue
									}
									hosts = append(hosts, host)
								}
							}
						}

						injectProxyURL(unitCfgMap, hosts)
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
// Go http client is used to determine the proxy URL, to ensure consistent behavior across all components.
// Traffic through proxy is preferred if the proxy is defined for any of the hosts.
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

	// Check if a proxy is defined for the hosts
	for _, host := range hosts {
		request, err := http.NewRequest("GET", host, nil)
		if err != nil {
			continue
		}
		// not using http.ProxyFromEnvironment() to be able to change the environment in unit tests
		proxyURL, err := httpproxy.FromEnvironment().ProxyFunc()(request.URL)
		if err != nil {
			continue
		}
		if proxyURL != nil && proxyURL.String() != "" {
			m["proxy_url"] = proxyURL.String()
			return
		}
	}
}
