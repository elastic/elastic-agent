// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

// Package agentless exposes helpers for the agentless deployment mode, which is
// toggled by setting ELASTIC_AGENT_IS_AGENTLESS in the process environment.
package agentless

import "os"

// EnvName is the environment variable that indicates agentless mode when set
// (the value is ignored; presence alone is sufficient).
// Keep aligned with github.com/elastic/beats/v7/libbeat/beat.EnvAgentless.
const (
	IsAgentlessEnvName          = "ELASTIC_AGENT_IS_AGENTLESS"
	StateStoreInputTypesEnvName = "AGENTLESS_ELASTICSEARCH_STATE_STORE_INPUT_TYPES"
)

// IsAgentless reports whether agentless mode is enabled for this process.
func IsAgentless() bool {
	_, ok := os.LookupEnv(IsAgentlessEnvName)
	return ok
}
