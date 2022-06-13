// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package dir

import (
	"context"
	"os"

	"github.com/elastic/elastic-agent/pkg/component"
)

// Checker performs basic check that the install directory exists.
type Checker struct{}

// NewChecker returns a new Checker.
func NewChecker() *Checker {
	return &Checker{}
}

// Check checks that the install directory exists.
func (*Checker) Check(_ context.Context, _ component.Spec, _, installDir string) error {
	_, err := os.Stat(installDir)
	return err
}
