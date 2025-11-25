// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package configuration

// VariablesConfig is the configuration related to Agent variable substitution.
type VariablesConfig struct {
	AllowMissing bool `yaml:"allow_missing,omitempty" config:"allow_missing,omitempty" json:"allow_missing,omitempty"`
}
