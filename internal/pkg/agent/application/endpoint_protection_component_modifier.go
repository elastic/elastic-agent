// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package application

import (
	"github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/coordinator"
	"github.com/elastic/elastic-agent/internal/pkg/agent/protection"
	"github.com/elastic/elastic-agent/pkg/component"
)

// EndpointProtectionComponentModifier copies "agent.protection" properties to the top level "protection" for the endpoint input
// Endpoint uses uninstall_token_hash in order to verify uninstall command token
// and signing_key in order validate the action signature.
// Example:
//
//	{
//		....
//		"protection": {
//	        "enabled": true,
//	        "signing_key": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEqrEVMJBfAiW7Mz9ZHegwlB7n4deTASUa5LlJlDfuz0hxo/7WPc7gkVB5H8LgnObPfihgzML7rLsHPreWZTB10A==",
//	        "uninstall_token_hash": ""
//	    },
//	    "revision": 1,
//	    "type": "endpoint"
//	}
func EndpointProtectionComponentModifier() coordinator.ComponentsModifier {
	return func(comps []component.Component, cfg map[string]interface{}) ([]component.Component, error) {
		const protectionKey = "protection"
		for i, comp := range comps {
			if comp.InputSpec != nil && (comp.InputSpec.InputType == endpoint) {
				for j, unit := range comp.Units {
					if unit.Type == client.UnitTypeInput && (unit.Config.Type == endpoint) {
						unitCfgMap := unit.Config.Source.AsMap()

						agentProtection := protection.GetAgentProtection(cfg)
						if agentProtection != nil {
							// Inject agent.protection under the top level protection property for endpoint unit
							var am map[string]interface{}
							if v, ok := unitCfgMap[protectionKey]; ok {
								am, _ = v.(map[string]interface{})
							}
							if am == nil {
								am = make(map[string]interface{})
								unitCfgMap[protectionKey] = am
							}
							for k, v := range agentProtection {
								am[k] = v
							}
						}

						unitCfg, err := component.ExpectedConfig(unitCfgMap)
						if err != nil {
							return nil, err
						}
						unit.Config = unitCfg
						comp.Units[j] = unit
					}
				}
			}
			comps[i] = comp
		}
		return comps, nil
	}
}
