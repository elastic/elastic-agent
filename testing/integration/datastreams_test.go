//go:build integration

package integration

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net/http"
	"net/http/httputil"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"text/template"
	"time"

	"github.com/elastic/elastic-agent-libs/kibana"
	"github.com/elastic/elastic-agent/pkg/control/v2/client"
	atesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/tools"
	"github.com/elastic/elastic-agent/pkg/testing/tools/estools"
	"github.com/stretchr/testify/require"
)

func TestFlattenedDatastreamFleetPolicy(t *testing.T) {
	dsType := "logs"
	dsNamespace := strings.ToLower(fmt.Sprintf("%snamespace%d", t.Name(), rand.Uint64()))
	dsDataset := strings.ToLower(fmt.Sprintf("%s-dataset", t.Name()))
	numEvents := uint64(60)

	tempDir := t.TempDir()
	logFilePath := filepath.Join(tempDir, "log.log")
	generateLogFile(t, logFilePath, 2*time.Millisecond, numEvents)

	info := define.Require(t, define.Requirements{
		Local: false,
		Stack: &define.Stack{},
		Sudo:  true,
	})

	agentFixture, err := define.NewFixture(t, define.Version())
	if err != nil {
		t.Fatalf("could not create new fixture: %s", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	createPolicyReq := kibana.AgentPolicy{
		Name:        t.Name() + "--" + time.Now().Format(time.RFC3339Nano),
		Namespace:   info.Namespace,
		Description: "Test policy for " + t.Name(),
		MonitoringEnabled: []kibana.MonitoringEnabledOption{
			kibana.MonitoringEnabledLogs,
			kibana.MonitoringEnabledMetrics,
		},
		IsProtected: false,
	}
	installOpts := atesting.InstallOpts{
		NonInteractive: true,
		Force:          true,
	}

	policy, err := tools.InstallAgentWithPolicy(ctx,
		t,
		installOpts,
		agentFixture,
		info.KibanaClient,
		createPolicyReq)
	if err != nil {
		t.Fatalf("could not install Elastic-AGent with Policy: %s", err)
	}

	tmpl, err := template.New(t.Name() + "custom-log-policy").Parse(policyJSON)
	if err != nil {
		t.Fatalf("cannot parse template: %s", err)
	}

	agentPolicyBuffer := bytes.Buffer{}
	err = tmpl.Execute(&agentPolicyBuffer, plolicyVars{
		Name:        "Log-Input-" + t.Name() + "-" + time.Now().Format(time.RFC3339),
		PolicyID:    policy.ID,
		LogFilePath: logFilePath,
		Namespace:   dsNamespace,
		Dataset:     dsDataset,
	})
	if err != nil {
		t.Fatalf("could not render template: %s", err)
	}

	resp, err := info.KibanaClient.Connection.Send(
		http.MethodPost,
		"/api/fleet/package_policies",
		nil,
		nil,
		&agentPolicyBuffer)
	if err != nil {
		t.Fatalf("could not execute request to Kibana/Fleet: %s", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("received a non 200-OK when adding package to policy. "+
			"Status code: %d", resp.StatusCode)
		respDump, err := httputil.DumpResponse(resp, true)
		if err != nil {
			t.Fatalf("could not dump error response from Kibana: %s", err)
		}
		t.Log("Kibana error response")
		t.Log(string(respDump))
		t.FailNow()
	}

	ensureDocumentsInES := func() bool {
		docs, err := estools.GetLogsForDatastream(
			context.Background(), info.ESClient, dsType, dsDataset, dsNamespace)
		if err != nil {
			t.Logf("error quering ES, will retry later: %s", err)
		}

		if docs.Hits.Total.Value == int(numEvents) {
			return true
		}

		return false
	}

	require.Eventually(t, ensureDocumentsInES, 120*time.Second, time.Second,
		"could not get all expected documents form ES")
}

func TestFlattenedDatastreamStandalone(t *testing.T) {
	dsType := "logs"
	dsNamespace := fmt.Sprintf("%s-namespace-%d", t.Name(), rand.Uint64())
	dsDataset := fmt.Sprintf("%s-dataset", t.Name())
	numEvents := uint64(60)

	tempDir := t.TempDir()
	logFilePath := filepath.Join(tempDir, "log.log")
	generateLogFile(t, logFilePath, 2*time.Millisecond, numEvents)

	info := define.Require(t, define.Requirements{
		Local: false,
		Stack: &define.Stack{},
		Sudo:  true,
	})

	agentFixture, err := define.NewFixture(t,
		define.Version(), atesting.WithAllowErrors())
	if err != nil {
		t.Fatalf("could not create new fixture: %s", err)
	}

	tmpl, err := template.New("standalone-policy").Parse(standalonePolicy)
	if err != nil {
		t.Fatalf("cannot parse template: %s", err)
	}

	// The environment variables are set by the test runner.
	// If you're manually running the tests (go test) then you
	// will have to manually set them
	renderedPolicy := bytes.Buffer{}
	tmpl.Execute(&renderedPolicy, plolicyVars{
		LogFilePath: logFilePath,
		Dataset:     dsDataset,
		Namespace:   dsNamespace,
		Type:        dsType,

		ESHost:     os.Getenv("ELASTICSEARCH_HOST"),
		ESUsername: os.Getenv("ELASTICSEARCH_USERNAME"),
		ESPassword: os.Getenv("ELASTICSEARCH_PASSWORD"),
	})

	if err := agentFixture.Prepare(context.Background()); err != nil {
		t.Fatalf("cannot prepare Elastic-Agent: %s", err)
	}

	runCtx, cancelAgentRunCtx := context.WithCancel(context.Background())
	go func() {
		// make sure the test does not hang forever
		time.Sleep(30 * time.Second)
		t.Error("'test timeout': cancelling run context, the Elastic-Agent will exit")
		cancelAgentRunCtx()
	}()

	state := atesting.State{
		Configure:  renderedPolicy.String(),
		AgentState: atesting.NewClientState(client.Healthy),
		Components: map[string]atesting.ComponentState{
			"filestream-default": {
				State: atesting.NewClientState(client.Healthy),
				Units: map[atesting.ComponentUnitKey]atesting.ComponentUnitState{
					{
						UnitType: client.UnitTypeInput,
						UnitID:   "filestream-default-elastic-agent-input-id",
					}: {
						State: atesting.NewClientState(client.Healthy),
					},

					{
						UnitType: client.UnitTypeOutput,
						UnitID:   "filestream-default",
					}: {
						State: atesting.NewClientState(client.Healthy),
					},
				},
			},
		},
		After: func() error {
			ensureDocumentsInES := func() bool {
				docs, err := estools.GetLogsForDatastream(context.Background(), info.ESClient, dsType, dsDataset, dsNamespace)
				if err != nil {
					t.Logf("error quering ES, will retry later: %s", err)
				}

				if docs.Hits.Total.Value == 60 {
					return true
				}

				return false
			}

			require.Eventually(
				t,
				ensureDocumentsInES,
				2*time.Minute, time.Second,
				"did not find all expected documents")
			cancelAgentRunCtx()
			return nil
		},
	}

	if err := agentFixture.Run(runCtx, state); err != nil {
		if !errors.Is(err, context.Canceled) {
			t.Errorf("error running Elastic-Agent: %s", err)
		}
	}
}

// generateLogFile generates a log file by appending new lines every tick
// the lines are composed by the test name and the current time in RFC3339Nano
// This function spans a new goroutine and does not block
func generateLogFile(t *testing.T, fullPath string, tick time.Duration, events uint64) {
	t.Helper()
	f, err := os.Create(fullPath)
	if err != nil {
		t.Fatalf("could not create file '%s: %s", fullPath, err)
	}

	go func() {
		t.Helper()
		ticker := time.NewTicker(tick)
		t.Cleanup(ticker.Stop)

		done := make(chan struct{})
		t.Cleanup(func() { close(done) })

		defer func() {
			if err := f.Close(); err != nil {
				t.Errorf("could not close log file '%s': %s", fullPath, err)
			}
		}()

		i := uint64(0)
		for {
			select {
			case <-done:
				return
			case now := <-ticker.C:
				i++
				_, err := fmt.Fprintln(f, t.Name(), "Iteration: ", i, now.Format(time.RFC3339Nano))
				if err != nil {
					// The Go compiler does not allow me to call t.Fatalf from a non-test
					// goroutine, t.Errorf is our only option
					t.Errorf("could not write data to log file '%s': %s", fullPath, err)
					return
				}
				// make sure log lines are synced as quickly as possible
				if err := f.Sync(); err != nil {
					t.Errorf("could not sync file '%s': %s", fullPath, err)
				}
				if i == events {
					return
				}
			}
		}
	}()
}

type plolicyVars struct {
	Name        string
	PolicyID    string
	LogFilePath string
	ESHost      string
	ESPassword  string
	ESUsername  string
	Namespace   string
	Dataset     string
	Type        string
}

var policyJSON = `
{
  "policy_id": "{{.PolicyID}}",
  "package": {
    "name": "log",
    "version": "2.3.0"
  },
  "name": "{{.Name}}",
  "namespace": "{{.Namespace}}",
  "inputs": {
    "logs-logfile": {
      "enabled": true,
      "streams": {
        "log.logs": {
          "enabled": true,
          "vars": {
            "paths": [
              "{{.LogFilePath}}"
            ],
            "data_stream.dataset": "{{.Dataset}}"
          }
        }
      }
    }
  }
}`

var standalonePolicy = `
outputs:
  default:
    type: elasticsearch
    hosts:
      - "{{.ESHost}}:443"
    username: "{{.ESUsername}}"
    password: "{{.ESPassword}}"

inputs:
  - type: filestream
    id: elastic-agent-input-id
    streams:
      - id: filestream-input-id-1
        data_stream:
          dataset: "{{.Dataset}}"
        data_stream.namespace: "{{.Namespace}}"
        data_stream.type: "{{.Type}}"
        paths:
          - {{.LogFilePath}}

agent.monitoring:
  enabled: true
  logs: true
  metrics: true
`
