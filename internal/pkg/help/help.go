// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package help

import (
	"fmt"
	"strings"

	"github.com/elastic/elastic-agent/internal/pkg/release"
)

// We assume that we always have a semver out of release.Version() (what about "main" or "current")
var majorMinorVersion []string = strings.SplitN(release.Version(), ".", 3)[:2]
var troubleshootingURL string = fmt.Sprintf("https://www.elastic.co/guide/en/fleet/%s.%s/fleet-troubleshooting.html", majorMinorVersion[0], majorMinorVersion[1])
var troubleshootMessage = "For help, please see our troubleshooting guide at " + troubleshootingURL

// GetTroubleshootMessage will return a nice pointer to the troubleshooting docs for the current version.
// There is an equivalent function in the cmd package but it's embedded with other common Cobra command stuff.
func GetTroubleshootMessage() string {
	return troubleshootMessage
}
