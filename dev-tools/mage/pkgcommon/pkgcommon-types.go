// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package pkgcommon

// PackageType defines the file format of the package (e.g. zip, rpm, etc).
type PackageType int

// List of possible package types.
const (
	RPM PackageType = iota + 1
	Deb
	Zip
	TarGz
	Docker
)

var AllPackageTypes = []PackageType{
	RPM,
	Deb,
	Zip,
	TarGz,
	Docker,
}
