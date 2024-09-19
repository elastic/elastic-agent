// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package application

import (
	"encoding/pem"
	"errors"
	"fmt"
	"os"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/elastic/elastic-agent-libs/transport/tlscommon"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/coordinator"
	"github.com/elastic/elastic-agent/pkg/component"
	"github.com/elastic/elastic-agent/pkg/core/logger"
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

		compIdx, unitIdx, ok := findEndpointUnit(comps, client.UnitTypeInput)
		if !ok {
			return comps, nil
		}

		unit := comps[compIdx].Units[unitIdx]
		unitCfgMap := unit.Config.Source.AsMap()
		if signed, ok := cfg[signedKey]; ok {
			unitCfgMap[signedKey] = signed
		}

		unitCfg, err := component.ExpectedConfig(unitCfgMap)
		if err != nil {
			return nil, err
		}

		unit.Config = unitCfg
		comps[compIdx].Units[unitIdx] = unit

		return comps, nil
	}
}

// EndpointTLSComponentModifier decrypts the client TLS certificate key if it's
// passphrase-protected. It replaces the content of 'fleet.ssl.key'
// and 'certificate' with theirs decrypted version and removes
// 'key_passphrase_path'.
// It does so, ONLY for the client TLS configuration for mTLS used with
// fleet-server.
func EndpointTLSComponentModifier(log *logger.Logger) coordinator.ComponentsModifier {
	return func(comps []component.Component, cfg map[string]interface{}) ([]component.Component, error) {
		compIdx, unitIdx, ok := findEndpointUnit(comps, client.UnitTypeInput)
		if !ok {
			// endpoint not present, nothing to do
			return comps, nil
		}

		unit := comps[compIdx].Units[unitIdx]
		unitCfgMap := unit.Config.Source.AsMap()

		// ensure the following config exists:
		// fleet.ssl:
		//   key_passphrase_path
		//   certificate
		//   key
		fleetNode, ok := unitCfgMap["fleet"]
		if !ok {
			// if 'fleet' isn't, present nothing to do
			return comps, nil
		}
		fleetMap, ok := fleetNode.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("EndpointTLSComponentModifier: 'fleet' node isn't a map, it is: %T", fleetNode)
		}

		sslNode, ok := fleetMap["ssl"]
		if !ok {
			// 'ssl' node not present isn't an issue
			return comps, nil
		}
		sslMap, ok := sslNode.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("EndpointTLSComponentModifier: 'ssl' node isn't a map, it is: %T", sslNode)
		}

		keyPassPathI, ok := sslMap["key_passphrase_path"]
		if !ok {
			// if no key_passphrase_path, nothing to decrypt
			return comps, nil
		}
		keyPassPathStr, ok := keyPassPathI.(string)
		if !ok {
			return nil, errors.New("EndpointTLSComponentModifier: 'key_passphrase_path' isn't a string")
		}
		if keyPassPathStr == "" {
			// the key shouldn't be empty, but if it's, nothing to decrypt
			return comps, nil
		}

		keyI, ok := sslMap["key"]
		if !ok {
			// if there is a key_passphrase_path, the key must be present
			return nil, errors.New("EndpointTLSComponentModifier: 'key_passphrase_path' present, but 'key' isn't present")
		}
		keyStr, ok := keyI.(string)
		if !ok {
			return nil, fmt.Errorf("EndpointTLSComponentModifier: 'key' isn't a string, it's %T", keyI)
		}

		certI, ok := sslMap["certificate"]
		if !ok {
			// if there is a key_passphrase_path, the certificate must be present
			return nil, errors.New("EndpointTLSComponentModifier: 'key_passphrase_path' present, but 'certificate' isn't present")
		}
		certStr, ok := certI.(string)
		if !ok {
			return nil, errors.New("EndpointTLSComponentModifier: 'certificate' isn't a string")
		}

		// all SSL config exists and the certificate key is passphrase protected,
		// now decrypt the key

		pass, err := os.ReadFile(keyPassPathStr)
		if err != nil {
			return nil, fmt.Errorf("EndpointTLSComponentModifier: failed to read client certificate passphrase file: %w", err)
		}

		// we don't really support encrypted certificates, but it's how
		// tlscommon.LoadCertificate does. Thus, let's keep the same behaviour.
		// Also, tlscommon.LoadCertificate 'loses' the type of the private key.
		// It stores they private key as an interface and there is no way to
		// retrieve the type os the private key without a type assertion.
		// Therefore, instead of manually checking the type, which would mean
		// to check for all supported private key types and keep it up to date,
		// better to load the certificate and its key directly from the PEM file.
		cert, err := tlscommon.ReadPEMFile(log,
			certStr, string(pass))
		if err != nil {
			return nil, fmt.Errorf("EndpointTLSComponentModifier: unable to load TLS certificate: %w", err)
		}
		key, err := tlscommon.ReadPEMFile(log,
			keyStr,
			string(pass))
		if err != nil {
			return nil, fmt.Errorf("EndpointTLSComponentModifier: unable to load TLS certificate key: %w", err)
		}

		// tlscommon.ReadPEMFile only removes the 'DEK-Info' header, not the
		// 'Proc-Type', so remove it now. Create a pem.Block to avoid editing
		// the PEM data manually:
		keyBlock, _ := pem.Decode(key)
		delete(keyBlock.Headers, "Proc-Type")
		key = pem.EncodeToMemory(keyBlock)

		// remove 'key_passphrase_path' as the certificate key isn't encrypted
		// anymore.
		delete(sslMap, "key_passphrase_path")

		// update the certificate and its key with their decrypted version.
		sslMap["certificate"] = string(cert)
		sslMap["key"] = string(key)

		unitCfg, err := component.ExpectedConfig(unitCfgMap)
		if err != nil {
			return nil, fmt.Errorf("EndpointTLSComponentModifier: could not covert modified config to expected config: %w", err)
		}

		unit.Config = unitCfg
		comps[compIdx].Units[unitIdx] = unit

		return comps, nil
	}
}

// findEndpointUnit finds the endpoint component and its unit of type 'unitType'.
// It returns the component and unit index and true if found, if not, it returns
// 0, 0, false.
func findEndpointUnit(comps []component.Component, unitType client.UnitType) (int, int, bool) {
	// find the endpoint component
	for compIdx, comp := range comps {
		if comp.InputSpec != nil && comp.InputSpec.InputType != endpoint {
			continue
		}

		for unitIdx, unit := range comp.Units {
			if unit.Type != unitType {
				continue
			}

			return compIdx, unitIdx, true
		}
	}
	return 0, 0, false
}
