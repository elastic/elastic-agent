// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package manifest

import v1 "github.com/elastic/elastic-agent/pkg/api/v1"

func GetFullVersion(manifest *v1.PackageManifest) string {
	version := manifest.Package.Version
	if manifest.Package.Snapshot {
		version += "-SNAPSHOT"
	}
	return version
}
