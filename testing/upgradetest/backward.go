package upgradetest

import (
	"fmt"
	"github.com/elastic/elastic-agent/pkg/version"
)

// BackwardTwoMinors gets the version two minors ago from the passed in version.
//
// This ensures that in the case that a version bump just happened that there will
// at least be a release that exists two minors before.
func BackwardTwoMinors(ver string) (string, error) {
	upgradeFromVersion, err := version.ParseVersion(ver)
	if err != nil {
		return "", fmt.Errorf("failed to parse version %q: %w", ver, err)
	}
	previousVersion, err := upgradeFromVersion.GetPreviousMinor()
	if err != nil {
		return "", fmt.Errorf("failed to get first previous version: %w", err)
	}
	previousVersion, err = previousVersion.GetPreviousMinor()
	if err != nil {
		return "", fmt.Errorf("failed to get second previous version: %w", err)
	}
	return previousVersion.CoreVersion(), nil
}
