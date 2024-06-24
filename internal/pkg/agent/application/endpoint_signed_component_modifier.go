// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package application

import (
	"github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/coordinator"
	"github.com/elastic/elastic-agent/pkg/component"
)

// EndpointSignedComponentModifier copies "signed" properties to the top level "signed" for the endpoint input.
// Enpoint team want to be able to validate the signature and parse the signed configuration (not trust the agent).
// Endpoint uses uninstall_token_hash in order to verify uninstall command token
// and signing_key in order validate the action signature.
// Example:
//
//	{
//		....
//		"signed": {
//			"data": "eyJpZCI6ImFhZWM4OTYwLWJiYjAtMTFlZC1hYzBkLTVmNjI0YTQxZjM4OCIsImFnZW50Ijp7InByb3RlY3Rpb24iOnsiZW5hYmxlZCI6dHJ1ZSwidW5pbnN0YWxsX3Rva2VuX2hhc2giOiIiLCJzaWduaW5nX2tleSI6Ik1Ga3dFd1lIS29aSXpqMENBUVlJS29aSXpqMERBUWNEUWdBRW1tckhDSTdtZ2tuZUJlYVJkc2VkQXZBU2l0UHRLbnpPdUlzeHZJRWdGTkFLVlg3MWpRTTVmalo1eUdsSDB0TmJuR2JrU2pVM0VEVUZsOWllQ1J0ME5nPT0ifX19",
//			"signature": "MEUCIQCWoScyJW0dejHFxXBTEcSCOZiBHRVMjuJRPwFCwOdA1QIgKrtKUBzkvVeljRtJyMXfD8zIvWjrMzqhSkgjNESPW5E="
//		},
//	    "revision": 1,
//	    "type": "endpoint"
//	}
func EndpointSignedComponentModifier() coordinator.ComponentsModifier {
	return func(comps []component.Component, cfg map[string]interface{}) ([]component.Component, error) {
		const signedKey = "signed"
		for i, comp := range comps {
			if comp.InputSpec != nil && (comp.InputSpec.InputType == endpoint) {
				for j, unit := range comp.Units {
					if unit.Type == client.UnitTypeInput && (unit.Config.Type == endpoint) {
						unitCfgMap := unit.Config.Source.AsMap()
						if signed, ok := cfg[signedKey]; ok {
							unitCfgMap[signedKey] = signed
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
