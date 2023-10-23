package integration

import (
	"context"
	"os/exec"
	"runtime"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-libs/kibana"
	integrationtest "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/tools/check"
	"github.com/elastic/elastic-agent/pkg/testing/tools/fleettools"
)

func TestAgentOnDockerEnroll(t *testing.T) {
	stack := define.Require(t, define.Requirements{
		Stack: &define.Stack{},
		OS:    []define.OS{{Type: define.Container, Arch: define.AMD64}},
		// Docker needs sudo by default
		Sudo:  true,
		Local: false,
	})

	policy, err := stack.KibanaClient.CreatePolicy(
		context.Background(), defaultPolicy())
	require.NoError(t, err, "unable to create policy")

	t.Logf("Creating enrollment API key...")
	enrollmentToken, err := stack.KibanaClient.CreateEnrollmentAPIKey(
		context.Background(), kibana.CreateEnrollmentAPIKeyRequest{
			PolicyID: policy.ID,
		})
	require.NoError(t, err, "unable to create enrollment API key")

	fleetServerURL, err := fleettools.DefaultURL(stack.KibanaClient)
	require.NoError(t, err, "unable to get default Fleet Server URL")

	f := integrationtest.LocalFetcher(
		t.TempDir(),
		integrationtest.WithDockerOnly("complete"))

	res, err := f.Fetch(
		context.Background(), runtime.GOOS, runtime.GOARCH, define.Version())
	require.NoError(t, err, "could not create fetcher result")

	err = res.Fetch(context.Background(), t, t.TempDir())
	require.NoError(t, err, "failed to local fetch docker image")

	// docker run \
	//  --env FLEET_ENROLL=1 \
	//  --env FLEET_URL=https://fleet-url:8220/ \
	//  --env FLEET_ENROLLMENT_TOKEN=SOME_TOKEN \
	//  docker.elastic.co/beats/elastic-agent:8.12.0-SNAPSHOT
	cmd := exec.Command("docker", "run",
		"--env", "FLEET_ENROLL=1",
		"--env", "FLEET_URL="+fleetServerURL,
		"--env", "FLEET_ENROLLMENT_TOKEN="+enrollmentToken.APIKey,
		"docker.elastic.co/beats/elastic-agent:"+define.Version())
	out, err := cmd.CombinedOutput()
	require.NoErrorf(t, err, "failed running agent on docker. Output: %s", out)

	assert.Eventually(
		t,
		check.FleetAgentStatus(t, stack.KibanaClient, policy.ID, check.FleetStatusOnline),
		5*time.Minute,
		10*time.Second,
		"Elastic Agent status is not online",
	)
}

func defaultPolicy() kibana.AgentPolicy {
	policyUUID := uuid.New().String()

	createPolicyReq := kibana.AgentPolicy{
		Name:        "test-policy-" + policyUUID,
		Namespace:   "default",
		Description: "Test policy " + policyUUID,
		MonitoringEnabled: []kibana.MonitoringEnabledOption{
			kibana.MonitoringEnabledLogs,
			kibana.MonitoringEnabledMetrics,
		},
	}
	return createPolicyReq
}
