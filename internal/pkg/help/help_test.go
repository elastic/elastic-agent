package help

import (
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/elastic/elastic-agent/version"
)

func TestGetTroubleshootMessage(t *testing.T) {
	versionTokens := strings.Split(version.GetDefaultVersion(), ".")
	assert.Equal(t, majorMinorVersion, versionTokens[:2])
	assert.Contains(t, troubleshootingURL, versionTokens[0]+"."+versionTokens[1])
	_, err := url.ParseRequestURI(troubleshootingURL)
	assert.NoError(t, err)
	assert.Contains(t, GetTroubleshootMessage(), troubleshootingURL)
}
