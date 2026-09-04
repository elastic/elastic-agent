// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build securityonly

package component

// variantAllowedInputTypes is the set of input type names that are actually
// compiled into the elastic-otel-collector binary for the security-only
// variant distribution.
//
// Filebeat: only filestream, log, and syslog inputs are compiled in
// (all x-pack filebeat inputs are excluded).
// Metricbeat: only the linux, system, and windows modules are compiled in.
// Osquerybeat: all osquery inputs.
//
// This list must be kept in sync with the securityonly build tags in the
// beats submodule (elastic-agent-security-only branch).
var variantAllowedInputTypes = map[string]struct{}{
	// filebeat
	"filestream": {},
	"log":        {},
	"syslog":     {},
	// metricbeat
	"linux/metrics":   {},
	"system/metrics":  {},
	"windows/metrics": {},
	// osquerybeat
	"osquery": {},
}
