// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build edr

package component

// flavorAllowedInputTypes is the set of input type names that are actually
// compiled into the elastic-otel-collector binary for the EDR
// flavor.
//
// Filebeat: only filestream, log, and syslog inputs are compiled in, plus
// journald on Linux and winlog on Windows (all x-pack filebeat inputs are
// excluded).
// Metricbeat: only the linux, system, and windows modules are compiled in.
// Auditbeat: only the auditd and file_integrity modules are compiled in.
// Osquerybeat: all osquery inputs.
//
// This list must be kept in sync with the edr build tags in the
// beats submodule (elastic-agent-EDR branch).
var flavorAllowedInputTypes = map[string]struct{}{
	// filebeat
	"filestream": {},
	"log":        {},
	"syslog":     {},
	"winlog":     {},
	"journald":   {},
	// metricbeat
	"linux/metrics":   {},
	"system/metrics":  {},
	"windows/metrics": {},
	// auditbeat
	"audit/auditd":         {},
	"audit/file_integrity": {},
	// osquerybeat
	"osquery": {},
}
