// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package application

import _ "embed"

// DefaultAgentFleetConfig is the content of the default configuration when we enroll a beat, the elastic-agent.yml
// will be replaced with this variables.
//
//go:embed elastic-agent.fleet.yml
var DefaultAgentFleetConfig []byte
