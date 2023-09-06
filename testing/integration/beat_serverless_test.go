// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

// //go:build integration

package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	atesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/tools"
)

type BeatRunner struct {
	suite.Suite
	requirementsInfo *define.Info
	agentFixture     *atesting.Fixture

	// connection info
	ESHost  string
	user    string
	pass    string
	kibHost string

	testUuid     string
	testbeatName string
}

func TestMetricbeatSeverless(t *testing.T) {
	info := define.Require(t, define.Requirements{
		OS: []define.OS{
			{Type: define.Linux},
		},
		Stack: &define.Stack{},
		Local: false,
		Sudo:  true,
	})

	suite.Run(t, &BeatRunner{requirementsInfo: info})
}

func (runner *BeatRunner) SetupSuite() {
	runner.T().Logf("In SetupSuite")

	runner.testbeatName = os.Getenv("TEST_BINARY_NAME")
	if runner.testbeatName == "" {
		runner.T().Fatalf("TEST_BINARY_NAME must be set")
	}
	if runner.testbeatName == "elastic-agent" {
		runner.T().Skipf("tests must be run against a beat, not elastic-agent")
	}

	if runner.testbeatName != "filebeat" && runner.testbeatName != "metricbeat" {
		runner.T().Skip("test only supports metricbeat or filebeat")
	}
	runner.T().Logf("running serverless tests with %s", runner.testbeatName)

	agentFixture, err := define.NewFixtureWithBinary(runner.T(), define.Version(), runner.testbeatName, "/home/ubuntu", atesting.WithRunLength(time.Minute), atesting.WithAdditionalArgs([]string{"-E", "output.elasticsearch.allow_older_versions=true"}))
	runner.agentFixture = agentFixture
	require.NoError(runner.T(), err)

	// the require.* code will fail without these, so assume the values are non-nil
	runner.ESHost = os.Getenv("ELASTICSEARCH_HOST")
	runner.user = os.Getenv("ELASTICSEARCH_USERNAME")
	runner.pass = os.Getenv("ELASTICSEARCH_PASSWORD")
	runner.kibHost = os.Getenv("KIBANA_HOST")

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	beatOutConfig := `
output.elasticsearch:
  hosts: ["%s"]
  username: %s
  password: %s
setup.kibana:
  host: %s
metricbeat.config.modules:
  path: ${path.config}/modules.d/*.yml
processors:
  - add_fields:
      target: host
      fields:
        test-id: %s
`
	if runner.testbeatName == "filebeat" {
		beatOutConfig = `
output.elasticsearch:
  hosts: ["%s"]
  username: %s
  password: %s
setup.kibana:
  host: %s
filebeat.config.modules:
  - modules: system
    syslog:
      enabled: true
    auth:
      enabled: true
processors:
  - add_fields:
      target: host
      fields:
        test-id: %s
`
	}

	// beats likes to add standard ports to URLs that don't have them, and ESS will sometimes return a URL without a port, assuming :443
	// so try to fix that here
	fixedKibanaHost := runner.kibHost
	parsedKibana, err := url.Parse(runner.kibHost)
	require.NoError(runner.T(), err)
	if parsedKibana.Port() == "" {
		fixedKibanaHost = fmt.Sprintf("%s:443", fixedKibanaHost)
	}

	fixedESHost := runner.ESHost
	parsedES, err := url.Parse(runner.ESHost)
	require.NoError(runner.T(), err)
	if parsedES.Port() == "" {
		fixedESHost = fmt.Sprintf("%s:443", fixedESHost)
	}

	runner.T().Logf("configuring beats with %s / %s", fixedESHost, fixedKibanaHost)

	testUuid, err := uuid.NewV4()
	require.NoError(runner.T(), err)
	runner.testUuid = testUuid.String()
	parsedCfg := fmt.Sprintf(beatOutConfig, fixedESHost, runner.user, runner.pass, fixedKibanaHost, testUuid.String())
	err = runner.agentFixture.WriteFileToWorkDir(ctx, parsedCfg, fmt.Sprintf("%s.yml", runner.testbeatName))
	require.NoError(runner.T(), err)
}

// run the beat with default metricsets, ensure no errors in logs + data is ingested
func (runner *BeatRunner) TestRunAndCheckData() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute*4)
	defer cancel()
	err := runner.agentFixture.Run(ctx)
	require.NoError(runner.T(), err)

	docs, err := tools.GetLatestDocumentMatchingQuery(ctx, runner.requirementsInfo.ESClient, map[string]interface{}{
		"match": map[string]interface{}{
			"host.test-id": runner.testUuid,
		},
	}, fmt.Sprintf("*%s*", runner.testbeatName))
	require.NoError(runner.T(), err)
	require.NotEmpty(runner.T(), docs.Hits.Hits)
}

// tests the [beat] setup --dashboards command
func (runner *BeatRunner) TestSetupDashboards() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute*3) //dashboards seem to take a while
	defer cancel()

	resp, err := runner.agentFixture.Exec(ctx, []string{"--path.home", runner.agentFixture.WorkDir(), "setup", "--dashboards"})
	assert.NoError(runner.T(), err)
	runner.T().Logf("got response from dashboard setup: %s", string(resp))
	require.True(runner.T(), strings.Contains(string(resp), "Loaded dashboards"))

	dashList, err := tools.GetDashboards(ctx, runner.requirementsInfo.KibanaClient)
	require.NoError(runner.T(), err)

	// interesting hack in cases where we don't have a clean environment
	// check to see if any of the dashboards were created recently
	found := false
	for _, dash := range dashList {
		if time.Since(dash.UpdatedAt) < time.Minute*5 {
			found = true
			break
		}
	}
	require.True(runner.T(), found, fmt.Sprintf("could not find dashboard newer than 5 minutes, out of %d dashboards", len(dashList)))

	runner.Run("export dashboards", runner.SubtestExportDashboards)

	// cleanup
	for _, dash := range dashList {
		err = tools.DeleteDashboard(ctx, runner.requirementsInfo.KibanaClient, dash.ID)
		if err != nil {
			runner.T().Logf("WARNING: could not delete dashboards after test: %s", err)
			break
		}
	}
}

// tests the [beat] export dashboard command
func (runner *BeatRunner) SubtestExportDashboards() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute*2)
	defer cancel()
	outDir := runner.T().TempDir()

	dashlist, err := tools.GetDashboards(ctx, runner.requirementsInfo.KibanaClient)
	require.NoError(runner.T(), err)
	require.NotEmpty(runner.T(), dashlist)

	_, err = runner.agentFixture.Exec(ctx, []string{"--path.home",
		runner.agentFixture.WorkDir(),
		"export",
		"dashboard", "--folder", outDir, "--id", dashlist[0].ID})
	assert.NoError(runner.T(), err)

	inFolder, err := os.ReadDir(filepath.Join(outDir, "/_meta/kibana/8/dashboard"))
	require.NoError(runner.T(), err)
	runner.T().Logf("got log contents: %#v", inFolder)
	require.NotEmpty(runner.T(), inFolder)
}

// NOTE for the below tests: the testing framework doesn't guarantee a new stack instance each time,
// which means we might be running against a stack where a previous test has already done setup.
// perhaps CI should run `mage integration:clean` first?

// tests the [beat] setup --pipelines command
func (runner *BeatRunner) TestSetupPipelines() {
	if runner.testbeatName != "filebeat" {
		runner.T().Skip("pipelines only available on filebeat")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	// need to actually enable something that has pipelines
	resp, err := runner.agentFixture.Exec(ctx, []string{"--path.home", runner.agentFixture.WorkDir(),
		"setup", "--pipelines", "--modules", "apache", "-M", "apache.error.enabled=true", "-M", "apache.access.enabled=true"})
	assert.NoError(runner.T(), err)

	runner.T().Logf("got response from pipeline setup: %s", string(resp))

	pipelines, err := tools.GetPipelines(ctx, runner.requirementsInfo.ESClient, "*filebeat*")
	require.NoError(runner.T(), err)
	require.NotEmpty(runner.T(), pipelines)

	/// cleanup
	err = tools.DeletePipelines(ctx, runner.requirementsInfo.ESClient, "*filebeat*")
	if err != nil {
		runner.T().Logf("WARNING: could not clean up pipelines: %s", err)
	}
}

// test beat setup --index-management with ILM disabled
func (runner *BeatRunner) TestIndexManagementNoILM() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	resp, err := runner.agentFixture.Exec(ctx, []string{"--path.home",
		runner.agentFixture.WorkDir(),
		"setup",
		"--index-management",
		"-E", "setup.ilm.enabled=false"})
	runner.T().Logf("got response from management setup: %s", string(resp))
	assert.NoError(runner.T(), err)

	tmpls, err := tools.GetIndexTemplatesForPattern(ctx, runner.requirementsInfo.ESClient, fmt.Sprintf("*%s*", runner.testbeatName))
	require.NoError(runner.T(), err)
	for _, tmpl := range tmpls.IndexTemplates {
		runner.T().Logf("got template: %s", tmpl.Name)
	}
	require.NotEmpty(runner.T(), tmpls.IndexTemplates)

	runner.Run("export templates", runner.SubtestExportTemplates)
	runner.Run("export index patterns", runner.SubtestExportIndexPatterns)

	// cleanup
	err = tools.DeleteIndexTemplatesDataStreams(ctx, runner.requirementsInfo.ESClient, fmt.Sprintf("*%s*", runner.testbeatName))
	if err != nil {
		runner.T().Logf("WARNING: could not clean up index templates/data streams: %s", err)
	}
}

// tests beat setup --index-management with ILM explicitly set
// On serverless, this should fail.
// Will not pass right now, may need to change
func (runner *BeatRunner) TestIndexManagementILMEnabledFail() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	info, err := tools.GetPing(ctx, runner.requirementsInfo.ESClient)
	require.NoError(runner.T(), err)

	if info.Version.BuildFlavor != "serverless" {
		runner.T().Skip("must run on serverless")
	}

	resp, err := runner.agentFixture.Exec(ctx, []string{"--path.home",
		runner.agentFixture.WorkDir(),
		"setup",
		"--index-management",
		"-E", "setup.ilm.enabled=true", "-E", "setup.ilm.overwrite=true"})
	runner.T().Logf("got response from management setup: %s", string(resp))
	assert.Error(runner.T(), err)
	assert.Contains(runner.T(), string(resp), "not supported")
}

// tests beat setup ilm-policy
// On serverless, this should fail
func (runner *BeatRunner) TestExportILMFail() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	info, err := tools.GetPing(ctx, runner.requirementsInfo.ESClient)
	require.NoError(runner.T(), err)

	if info.Version.BuildFlavor != "serverless" {
		runner.T().Skip("must run on serverless")
	}

	resp, err := runner.agentFixture.Exec(ctx, []string{"--path.home",
		runner.agentFixture.WorkDir(),
		"export", "ilm-policy", "-E", "setup.ilm.overwrite=true"})
	runner.T().Logf("got response from management setup: %s", string(resp))
	assert.Error(runner.T(), err)
	assert.Contains(runner.T(), string(resp), "not supported")

}

func (runner *BeatRunner) SubtestExportTemplates() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute*2)
	defer cancel()
	outDir := runner.T().TempDir()

	_, err := runner.agentFixture.Exec(ctx, []string{"--path.home",
		runner.agentFixture.WorkDir(),
		"export",
		"template", "--dir", outDir})
	assert.NoError(runner.T(), err)

	inFolder, err := os.ReadDir(filepath.Join(outDir, "/template"))
	require.NoError(runner.T(), err)
	runner.T().Logf("got log contents: %#v", inFolder)
	require.NotEmpty(runner.T(), inFolder)
}

func (runner *BeatRunner) SubtestExportIndexPatterns() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute*2)
	defer cancel()

	rawPattern, err := runner.agentFixture.Exec(ctx, []string{"--path.home",
		runner.agentFixture.WorkDir(),
		"export",
		"index-pattern"})
	assert.NoError(runner.T(), err)

	idxPattern := map[string]interface{}{}

	err = json.Unmarshal(rawPattern, &idxPattern)
	require.NoError(runner.T(), err)
	require.NotNil(runner.T(), idxPattern["attributes"])
}
