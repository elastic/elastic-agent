// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package manager

import (
	"fmt"

	"go.opentelemetry.io/collector/confmap"
)

const (
	// opampExtensionName is the OTel component type name of the opamp extension.
	opampExtensionName = "opamp"

	// opampPollingInterval is how often the collector polls the manager's OpAMP
	// server for ServerToAgent messages and uploads its current Health. We pick a
	// short interval to match the responsiveness of the previous healthcheckv2
	// polling loop. opampextension's HTTP transport default is 30s.
	opampPollingInterval = "1s"

	// opampAuthorizationHeader is the HTTP header used to carry the per-manager
	// shared secret. The OpAMP server rejects requests with a missing or
	// non-matching value.
	opampAuthorizationHeader = "Authorization"
)

// injectOpAMPExtension injects the opamp extension into config, pointing it at
// the manager's local OpAMP HTTP server. The extension is configured to:
//   - report only Health (effective config and available components are disabled
//     so secrets in the merged config are not sent over loopback HTTP);
//   - authenticate to the server with a per-manager shared secret.
//
// extensionID is the full OTel component ID (e.g. "opamp/<uuid>"). instanceUID
// is a UUIDv7 string that remains stable across collector restarts of this
// manager. serverEndpoint is the URL of the manager's OpAMP server (e.g.
// "http://127.0.0.1:1234/v1/opamp"). secret is the bearer token that the
// extension must send in the Authorization header.
func injectOpAMPExtension(conf *confmap.Conf, extensionID, instanceUID, serverEndpoint, secret string) error {
	return mergeWithExtensions(conf, confmap.NewFromStringMap(map[string]any{
		"extensions": map[string]any{
			extensionID: map[string]any{
				"server": map[string]any{
					"http": map[string]any{
						"endpoint":         serverEndpoint,
						"polling_interval": opampPollingInterval,
						"headers": map[string]any{
							opampAuthorizationHeader: fmt.Sprintf("Bearer %s", secret),
						},
					},
				},
				"instance_uid": instanceUID,
				"capabilities": map[string]any{
					"reports_health":               true,
					"reports_effective_config":     false,
					"reports_available_components": false,
				},
			},
		},
		"service": map[string]any{
			"extensions": []any{extensionID},
		},
	}))
}
