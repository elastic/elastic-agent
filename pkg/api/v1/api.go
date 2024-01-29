// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

// Package v1 contains definitions for elastic-agent/v1 objects
package v1

const VERSION = "co.elastic.agent/v1"

type apiObject struct {
	Version string `yaml:"version" json:"version"`
	Kind    string `yaml:"kind" json:"kind"`
}
