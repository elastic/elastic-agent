//go:build integration

package integration

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"testing"
	"text/template"
	"time"

	"github.com/elastic/elastic-agent-libs/kibana"
	atesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/tools"
	"github.com/gofrs/uuid/v5"
	"github.com/stretchr/testify/require"
)

//go:embed custom_log_package.json.tmpl
var customLogPackagePolicy string

func TestEscapingSecretsInPolicy(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Group: Default,
		Stack: &define.Stack{},
		Sudo:  true,
	})
	ctx := context.Background()

	fixture, err := define.NewFixtureFromLocalBuild(t, define.Version())
	require.NoError(t, err)
	installOpts := atesting.InstallOpts{
		NonInteractive: true,
		Force:          true,
		Privileged:     true,
	}

	polId := uuid.Must(uuid.NewV4()).String()
	policy := kibana.AgentPolicy{
		Name:        "test-policy-" + polId,
		Namespace:   "default",
		Description: "Test policy " + polId,
		MonitoringEnabled: []kibana.MonitoringEnabledOption{
			kibana.MonitoringEnabledLogs,
			kibana.MonitoringEnabledMetrics,
		},
	}

	policyResp, err := tools.InstallAgentWithPolicy(ctx, t, installOpts, fixture, info.KibanaClient, policy)

	tmpl := template.Must(template.New("custom_log_package_policy").Parse(customLogPackagePolicy))
	pkgPolId := uuid.Must(uuid.NewV4()).String()

	templateVars := struct {
		policyId    string
		pkgPolicyId string
	}{
		policyId:    policyResp.AgentPolicy.ID,
		pkgPolicyId: pkgPolId,
	}

	var tmplBuf bytes.Buffer
	err = tmpl.Execute(&tmplBuf, templateVars)
	require.NoError(t, err)

	pkgPolicyReq := kibana.PackagePolicyRequest{}
	err = json.Unmarshal(tmplBuf.Bytes(), &pkgPolicyReq)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()

	// pkgResp, err := info.KibanaClient.InstallFleetPackage(ctx, pkgPolicyReq)
	// require.NoError(t, err)
	_, err = info.KibanaClient.InstallFleetPackage(ctx, pkgPolicyReq)
	// require.NoError(t, err)
	require.Error(t, err)
}
