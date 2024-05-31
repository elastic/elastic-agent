//go:build integration

package newexp

import (
	"io"
	"net/http"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/elastic/elastic-agent/pkg/testing/define"
)

func TestDrill(t *testing.T) {
	// assert that values set in TestMain is available for tests
	assert.Equal(t, "This is not a drill.", pkgVar)
	assert.Contains(t, os.Environ(), "TEST_ENV_VAR=This is not a drill.")
}

func TestDeployment(t *testing.T) {
	// assert that we get something usable from define directive
	info := define.Require(t, define.Requirements{
		Group: "Foo",
		Stack: &define.Stack{},
	})
	assert.NotEmpty(t, info.ESClient, "couldn't instantiate ES client")
	assert.NotEmpty(t, info.KibanaClient, "couldn't instantiate Kibana client")

	esInfoResp, err := info.ESClient.Info()
	assert.NoError(t, err, "error fetch ES info")
	defer esInfoResp.Body.Close()
	infoBytes, err := io.ReadAll(esInfoResp.Body)
	assert.NoError(t, err, "error reading ES info response body")
	t.Logf("ES info:\n%s\n", string(infoBytes))

	kibanaResponse, err := info.KibanaClient.Send(http.MethodGet, "/api/fleet/agents", nil, nil, nil)
	assert.NoError(t, err, "error pinging Kibana/Fleet")
	defer kibanaResponse.Body.Close()
	agentStatuses, err := io.ReadAll(kibanaResponse.Body)
	assert.NoError(t, err, "error reading Fleet agents response body")
	t.Logf("Fleet Agents:\n%s\n", string(agentStatuses))
}
