// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

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
	"regexp"
	"strings"
	"testing"
	"text/template"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-libs/kibana"
	"github.com/elastic/elastic-agent/pkg/control/v2/client"
	atesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/tools/estools"
	"github.com/elastic/elastic-agent/version"
	"github.com/elastic/elastic-transport-go/v8/elastictransport"
)

func testFlattenedDatastreamFleetPolicy(
	t *testing.T,
	ctx context.Context,
	info *define.Info,
	agentFixture *atesting.Fixture,
	policy kibana.PolicyResponse,
) {
	dsType := "logs"
	dsNamespace := cleanString(fmt.Sprintf("%snamespace%d", t.Name(), rand.Uint64()))
	dsDataset := cleanString(fmt.Sprintf("%s-dataset", t.Name()))
	numEvents := 60

	tempDir := t.TempDir()
	logFilePath := filepath.Join(tempDir, "log.log")
	generateLogFile(t, logFilePath, 2*time.Millisecond, numEvents)

	agentFixture, err := define.NewFixture(t, define.Version())
	if err != nil {
		t.Fatalf("could not create new fixture: %s", err)
	}

	// 1. Prepare a request to add an integration to the policy
	tmpl, err := template.New(t.Name() + "custom-log-policy").Parse(policyJSON)
	if err != nil {
		t.Fatalf("cannot parse template: %s", err)
	}

	// The time here ensures there are no conflicts with the integration name
	// in Fleet.
	agentPolicyBuilder := strings.Builder{}
	err = tmpl.Execute(&agentPolicyBuilder, plolicyVars{
		Name:        "Log-Input-" + t.Name() + "-" + time.Now().Format(time.RFC3339),
		PolicyID:    policy.ID,
		LogFilePath: logFilePath,
		Namespace:   dsNamespace,
		Dataset:     dsDataset,
	})
	if err != nil {
		t.Fatalf("could not render template: %s", err)
	}
	// We keep a copy of the policy for debugging prurposes
	agentPolicy := agentPolicyBuilder.String()

	// 2. Call Kibana to create the policy.
	// Docs: https://www.elastic.co/guide/en/fleet/current/fleet-api-docs.html#create-integration-policy-api
	resp, err := info.KibanaClient.Connection.Send(
		http.MethodPost,
		"/api/fleet/package_policies",
		nil,
		nil,
		bytes.NewBufferString(agentPolicy))
	if err != nil {
		t.Fatalf("could not execute request to Kibana/Fleet: %s", err)
	}
	if resp.StatusCode != http.StatusOK {
		// On error dump the whole request response so we can easily spot
		// what went wrong.
		t.Errorf("received a non 200-OK when adding package to policy. "+
			"Status code: %d", resp.StatusCode)
		respDump, err := httputil.DumpResponse(resp, true)
		if err != nil {
			t.Fatalf("could not dump error response from Kibana: %s", err)
		}
		// Make debugging as easy as possible
		t.Log("================================================================================")
		t.Log("Kibana error response:")
		t.Log(string(respDump))
		t.Log("================================================================================")
		t.Log("Rendered policy:")
		t.Log(agentPolicy)
		t.Log("================================================================================")
		t.FailNow()
	}

	require.Eventually(
		t,
		ensureDocumentsInES(t, ctx, info.ESClient, dsType, dsDataset, dsNamespace, numEvents),
		120*time.Second,
		time.Second,
		"could not get all expected documents form ES")
}

func TestFlattenedDatastreamStandalone(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Local: false,
		Stack: &define.Stack{
			Version: version.Agent + "-SNAPSHOT",
		},
		Sudo: true,
	})

	ctx := context.Background()
	dsType := "logs"
	dsNamespace := fmt.Sprintf("%s-namespace-%d", t.Name(), rand.Uint64())
	dsDataset := fmt.Sprintf("%s-dataset", t.Name())
	numEvents := 60

	tempDir := t.TempDir()
	logFilePath := filepath.Join(tempDir, "log.log")
	generateLogFile(t, logFilePath, 2*time.Millisecond, numEvents)

	agentFixture, err := define.NewFixture(
		t,
		define.Version(),
		atesting.WithAllowErrors())
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

	// 1. The first thing to do is to prepare the fixture.
	if err := agentFixture.Prepare(ctx); err != nil {
		t.Fatalf("cannot prepare Elastic-Agent: %s", err)
	}

	// 2. Create a context with cancel to easily stop the Elastic-Agent
	runCtx, cancelAgentRunCtx := context.WithCancel(ctx)
	go func() {
		// make sure the test does not hang forever
		time.Sleep(90 * time.Second)
		t.Error("'test timeout': cancelling run context, the Elastic-Agent will exit")
		cancelAgentRunCtx()
	}()

	// 3. Define the "desired state". Here we define the desired state
	// for Elastic-Agent and its components. Once this state is reached the
	// `After` hook is called, the actual test code goes there. Anything that needs
	// to be done after the Elastic-Agent is running goes there. In this case we only
	// need to assert the documents are correctly ingested in ES.
	//
	// `Configure` contains the raw YAML policy for the Elastic-Agent. Because `agentFixture.Run` starts
	// the Elastic-Agent in test mode (`--testing-mode`), it will ignore the `elastic-agent.yaml`
	// and wait to receive the full configuration via gRPC, hence there is no need to call the
	// `agent.Fixture.Configure` method.
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
			require.Eventually(
				t,
				ensureDocumentsInES(t, runCtx, info.ESClient, dsType, dsDataset, dsNamespace, numEvents),
				2*time.Minute, time.Second,
				"did not find all expected documents")
			cancelAgentRunCtx()
			return nil
		},
	}

	// 4. Start the Elastic-Agent. `agentFixture.Run` will block until
	// the Elastic-Agent exits or `runCtx` is cancelled.
	if err := agentFixture.Run(runCtx, state); err != nil {
		if !errors.Is(err, context.Canceled) {
			t.Errorf("error running Elastic-Agent: %s", err)
		}
	}
}

// ensureDocumentsInES asserts the documents were ingested into the correct
// datastream
func ensureDocumentsInES(
	t *testing.T,
	ctx context.Context,
	esClient elastictransport.Interface,
	dsType, dsDataset, dsNamespace string,
	numEvents int,
) func() bool {

	f := func() bool {
		t.Helper()

		docs, err := estools.GetLogsForDatastream(ctx, esClient, dsType, dsDataset, dsNamespace)
		if err != nil {
			t.Logf("error quering ES, will retry later: %s", err)
		}

		if docs.Hits.Total.Value == numEvents {
			return true
		}

		return false

	}

	return f
}

// generateLogFile generates a log file by appending new lines every tick
// the lines are composed by the test name and the current time in RFC3339Nano
// This function spans a new goroutine and does not block
func generateLogFile(t *testing.T, fullPath string, tick time.Duration, events int) {
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

		i := 0
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

func cleanString(s string) string {
	return nonAlphanumericRegex.ReplaceAllString(strings.ToLower(s), "")
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

var nonAlphanumericRegex = regexp.MustCompile(`[^a-zA-Z0-9 ]+`)

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
