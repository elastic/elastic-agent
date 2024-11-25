//go:build integration

package integration

import (
	"context"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/elastic/elastic-agent-libs/kibana"
	atesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/tools"
	"github.com/elastic/elastic-agent/pkg/testing/tools/check"
	"github.com/elastic/elastic-agent/pkg/testing/tools/fleettools"
	"github.com/gofrs/uuid/v5"
	"github.com/stretchr/testify/require"
)

func TestEnrollUnprivileged(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Group: Default,
		Stack: &define.Stack{},
		Sudo:  true,
	})
	t.Run("unenrolled unprivileged agent re-enrolls successfully using root user", func(t *testing.T) {
		ctx := context.Background()
		fixture, err := define.NewFixtureFromLocalBuild(t, define.Version())
		require.NoError(t, err)
		installOpts := atesting.InstallOpts{
			NonInteractive: true,
			Force:          true,
			Privileged:     false,
		}

		randId := uuid.Must(uuid.NewV4()).String()
		policyReq := kibana.AgentPolicy{
			Name:        "test-policy-" + randId,
			Namespace:   "default",
			Description: "Test policy " + randId,
			MonitoringEnabled: []kibana.MonitoringEnabledOption{
				kibana.MonitoringEnabledLogs,
				kibana.MonitoringEnabledMetrics,
			},
		}
		policy, err := info.KibanaClient.CreatePolicy(ctx, policyReq)
		require.NoError(t, err)

		enrollmentApiKey, err := tools.CreateEnrollmentToken(t, ctx, info.KibanaClient, policy.ID)
		require.NoError(t, err)

		err = tools.InstallAgentForPolicyWithToken(ctx, t, installOpts, fixture, info.KibanaClient, policy.ID, enrollmentApiKey)
		require.NoError(t, err)

		hostname, err := os.Hostname()
		require.NoError(t, err)

		agent, err := fleettools.GetAgentByPolicyIDAndHostnameFromList(ctx, info.KibanaClient, policy.ID, hostname)
		require.NoError(t, err)

		_, err = info.KibanaClient.UnEnrollAgent(ctx, kibana.UnEnrollAgentRequest{ID: agent.ID})
		require.NoError(t, err)

		enrollUrl, err := fleettools.DefaultURL(ctx, info.KibanaClient)
		require.NoError(t, err)

		enrollArgs := []string{"elastic-agent", "enroll", "--url", enrollUrl, "--enrollment-token", enrollmentApiKey.APIKey, "--force"}

		out, err := exec.CommandContext(ctx, "sudo", enrollArgs...).CombinedOutput()
		require.NoError(t, err)

		t.Logf(">>> Enroll succeeded. Output: %s", out)
		timeout := 2 * time.Minute
		if deadline, ok := ctx.Deadline(); ok {
			timeout = time.Until(deadline)
		}
		// Wait for Agent to be healthy
		require.Eventually(
			t,
			check.FleetAgentStatus(ctx, t, info.KibanaClient, policy.ID, "online"),
			timeout,
			10*time.Second,
			"Elastic Agent status is not online",
		)
	})
}
