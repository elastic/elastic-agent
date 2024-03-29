// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package version

import "fmt"

func GenerateAgentVersionWithSnapshotFlag(packageVersion string, snapshotFlag bool) (string, error) {

	if !snapshotFlag {
		return packageVersion, nil
	}

	parsedPackageVersion, err := ParseVersion(packageVersion)
	if err != nil {
		return "", fmt.Errorf("parsing package version string %q: %w", packageVersion, err)
	}
	prereleaseTokens := parsedPackageVersion.PrereleaseTokens()
	patchedPrereleaseTokens := make([]string, len(prereleaseTokens)+1)
	patchedPrereleaseTokens[0] = snapshotPrereleaseToken
	copy(patchedPrereleaseTokens[1:], prereleaseTokens)

	patchedPackageVersion := NewParsedSemVer(
		parsedPackageVersion.Major(),
		parsedPackageVersion.Minor(),
		parsedPackageVersion.Patch(),
		assemblePrereleaseStringFromTokens(patchedPrereleaseTokens),
		parsedPackageVersion.BuildMetadata(),
	)

	return patchedPackageVersion.String(), nil
}
