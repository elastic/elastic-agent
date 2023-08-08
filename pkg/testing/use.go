// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package testing

import (
	"fmt"

	"github.com/elastic/elastic-agent/pkg/component"
)

// UsableComponent defines a component that the fixture will set up and use.
//
// There is two different ways for defining a usable component.
//  1. Provide a `Name` only.
//     - This will instruct the fixture to keep this component from the fetched Elastic Agent. If the component
//     does not exist in the fetched Elastic Agent then `Prepare` of the fixture will fail.
//  2. Provide a `Name`, `BinaryPath`, and `Spec` or `SpecPath`.
//     - This will instruct the fixture to copy the binary of the component and write the defined specification
//     into the Elastic Agent components directory.
type UsableComponent struct {
	// Name is the name of the component to either initialize or keep from the components directory. See the
	// description above about the different ways to define a usable component.
	Name string
	// BinaryPath is the path to the component to copy into the components directory. See the
	// description above about the different ways to define a usable component.
	BinaryPath string
	// Spec is the specification definition for the component to be placed into the components directory. See the
	// description above about the different ways to define a usable component.
	Spec *component.Spec
	// SpecPath is the path to the specification file to copy into the components directory. See the
	// description above about the different ways to define a usable component.
	SpecPath string
	// SupportingFiles are the files that also need to be copied into the components directory.
	SupportingFiles []string
}

// Validate ensures correctness of component specification.
func (c *UsableComponent) Validate() error {
	if c.Name == "" {
		return fmt.Errorf("Name must be defined")
	}
	if c.BinaryPath != "" {
		if c.Spec == nil && c.SpecPath == "" {
			return fmt.Errorf("either Spec or SpecPath must be defined")
		}
		if c.Spec != nil && c.SpecPath != "" {
			return fmt.Errorf("both Spec or SpecPath cannot be defined")
		}
	}
	return nil
}
