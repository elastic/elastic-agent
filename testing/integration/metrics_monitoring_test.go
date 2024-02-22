package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/elastic/elastic-agent-libs/kibana"
	atesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/tools"
	"github.com/elastic/elastic-agent/pkg/testing/tools/estools"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type MetricsRunner struct {
	suite.Suite
	info         *define.Info
	agentFixture *atesting.Fixture

	ESHost string
}

func TestMetricsMonitoringCorrectBinaries(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Group: "fleet",
		Stack: &define.Stack{},
		Local: false, // requires Agent installation
		Sudo:  true,  // requires Agent installation
		OS: []define.OS{
			{Type: define.Linux},
			{Type: define.Windows},
		},
	})

	suite.Run(t, &MetricsRunner{info: info})
}

func (runner *MetricsRunner) SetupSuite() {
	fixture, err := define.NewFixture(runner.T(), define.Version())
	require.NoError(runner.T(), err)
	runner.agentFixture = fixture

	policyUUID := uuid.New().String()
	basePolicy := kibana.AgentPolicy{
		Name:        "test-policy-" + policyUUID,
		Namespace:   "default",
		Description: "Test policy " + policyUUID,
		MonitoringEnabled: []kibana.MonitoringEnabledOption{
			kibana.MonitoringEnabledLogs,
			kibana.MonitoringEnabledMetrics,
		},
	}

	unpr := false
	installOpts := atesting.InstallOpts{
		NonInteractive: true,
		Force:          true,
		Unprivileged:   &unpr,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	policyResp, err := tools.InstallAgentWithPolicy(ctx, runner.T(), installOpts, runner.agentFixture, runner.info.KibanaClient, basePolicy)
	require.NoError(runner.T(), err)

	runner.InstallPackage(ctx, "system", "1.53.1", "system_integration_setup.json", uuid.New().String(), policyResp.ID)

}

func (runner *MetricsRunner) InstallPackage(ctx context.Context, name string, version string, cfgFile string, policyUUID string, policyID string) {
	installPackage := kibana.PackagePolicyRequest{}

	jsonRaw, err := os.ReadFile(cfgFile)
	require.NoError(runner.T(), err)

	err = json.Unmarshal(jsonRaw, &installPackage)
	require.NoError(runner.T(), err)

	installPackage.Package.Version = version
	installPackage.ID = policyUUID
	installPackage.PolicyID = policyID
	installPackage.Namespace = "default"
	installPackage.Name = fmt.Sprintf("%s-long-test-%s", name, policyUUID)
	installPackage.Vars = map[string]interface{}{}

	runner.T().Logf("Installing %s package....", name)
	_, err = runner.info.KibanaClient.InstallFleetPackage(ctx, installPackage)
	require.NoError(runner.T(), err, "error creating fleet package")
}

func (runner *MetricsRunner) TestBeatsMetrics() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute*20)
	defer cancel()
	agentStatus, err := runner.agentFixture.ExecStatus(ctx)
	require.NoError(runner.T(), err)

	componentIds := []string{
		"system/metrics-default",
		"log-default",
		"beat/metrics-monitoring",
		"elastic-agent",
		"http/metrics-monitoring",
		"filestream-monitoring",
	}

	require.Eventually(runner.T(), func() bool {
		for _, cid := range componentIds {
			query := genESQuery(agentStatus.Info.ID, cid)
			res, err := estools.PerformQueryForRawQuery(ctx, query, ".ds-metrics*", runner.info.ESClient)
			require.NoError(runner.T(), err)
			runner.T().Logf("Fetched metrics for %s, got %d hits", cid, res.Hits.Total.Value)
			if res.Hits.Total.Value < 5 {
				return false
			}
		}
		return true
	}, time.Minute*10, time.Second*10, "could not fetch metrics for all known beats in default install: %v", componentIds)
}

func genESQuery(agentID string, componentID string) map[string]interface{} {
	queryRaw := map[string]interface{}{
		"query": map[string]interface{}{
			"bool": map[string]interface{}{
				"must": []map[string]interface{}{
					{
						"match": map[string]interface{}{
							"agent.id": agentID,
						},
					},
					{
						"match": map[string]interface{}{
							"component.id": componentID,
						},
					},
				},
			},
		},
	}

	return queryRaw
}
