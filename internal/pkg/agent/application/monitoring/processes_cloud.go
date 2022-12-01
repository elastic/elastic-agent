package monitoring

import (
	"strings"

	"github.com/elastic/elastic-agent/pkg/component"
)

func expectedCloudProcessID(c *component.Component) string {
	// Cloud explicitly looks for an ID of "apm-server" to determine if APM is in managed mode.
	// Ensure that this is the ID we use, in agent v2 the ID is usually "apm-default".
	// Otherwise apm-server won't be routable/accessible in cloud.
	// https://github.com/elastic/elastic-agent/issues/1731#issuecomment-1325862913
	if strings.Contains(c.InputSpec.BinaryName, "apm-server") {
		// cloud understands `apm-server-default` and does not understand `apm-default`
		return strings.Replace(c.ID, "apm-", "apm-server-", 1)
	}

	return c.ID
}

func matchesCloudProcessID(c *component.Component, id string) bool {
	// Similar to the case above, cloud currently makes a call to /processes/apm-server
	// to find the APM server address. Rather than change all of the monitoring in cloud,
	// it is easier to just make sure the existing ID maps to the APM server component.
	if strings.Contains(id, "apm-server") {
		if strings.Contains(c.InputSpec.BinaryName, "apm-server") {
			return true
		}
	}

	return id == c.ID
}
