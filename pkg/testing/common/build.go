// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package common

// Build describes a build and its paths.
type Build struct {
	// Version of the Elastic Agent build.
	Version string
	// Type of OS this build is for.
	Type string
	// Arch is architecture this build is for.
	Arch string
	// Path is the path to the build.
	Path string
	// SHA512 is the path to the SHA512 file.
	SHA512Path string
}
