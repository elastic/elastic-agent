// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package mage

import (
	"sync"

	"github.com/magefile/mage/mg"
)

var (
	buildMageOnce sync.Once
)

// IntegrationTestStep setups mage to be ran.
type IntegrationTestStep struct{}

// Name returns the mage name.
func (m *IntegrationTestStep) Name() string {
	return "mage"
}

// Use always returns false.
//
// This step should be defined in `StepRequirements` for the tester, for it
// to be used. It cannot be autodiscovered for usage.
func (m *IntegrationTestStep) Use(dir string) (bool, error) {
	return false, nil
}

// Setup ensures the mage binary is built.
//
// Multiple uses of this step will only build the mage binary once.
func (m *IntegrationTestStep) Setup(_ map[string]string) error {
	// Pre-build a mage binary to execute.
	buildMageOnce.Do(func() { mg.Deps(buildMage) })
	return nil
}

// Teardown does nothing.
func (m *IntegrationTestStep) Teardown(_ map[string]string) error {
	return nil
}
