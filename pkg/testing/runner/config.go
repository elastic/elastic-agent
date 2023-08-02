// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package runner

import (
	"errors"
)

// Config provides the configuration for running the runner.
type Config struct {
	AgentVersion      string
	AgentStackVersion string
	BuildDir          string
	GOVersion         string
	RepoDir           string
	DiagnosticsDir    string

	// Matrix enables matrix testing. This explodes each test to
	// run on all supported platforms the runner supports.
	Matrix bool

	// SingleTest only has the runner run that specific test.
	SingleTest string

	// VerboseMode passed along a verbose mode flag to tests
	VerboseMode bool

	// Timestamp enables timestamps on the console output.
	Timestamp bool

	// Testflags contains extra go test flags to be set when running tests
	TestFlags string

	// ExtraEnv contains extra environment flags to pass to the runner.
	ExtraEnv map[string]string
}

// Validate returns an error if the information is invalid.
func (c *Config) Validate() error {
	if c.AgentVersion == "" {
		return errors.New("field AgentVersion must be set")
	}
	if c.AgentStackVersion == "" {
		return errors.New("field AgentStackVersion must be set")
	}
	if c.BuildDir == "" {
		return errors.New("field BuildDir must be set")
	}
	if c.GOVersion == "" {
		return errors.New("field GOVersion must be set")
	}
	if c.RepoDir == "" {
		return errors.New("field RepoDir must be set")
	}
	return nil
}
