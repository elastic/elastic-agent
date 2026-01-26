// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration

package k8s

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/e2e-framework/klient/k8s"

	"github.com/elastic/elastic-agent/pkg/testing/define"
)

func TestKubernetesAgentService(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Stack: &define.Stack{},
		Local: false,
		Sudo:  false,
		OS: []define.OS{
			// only test the service container
			{Type: define.Kubernetes, DockerVariant: "service"},
		},
		Group: define.Kubernetes,
	})

	// read the service agent config
	serviceAgentYAML, err := os.ReadFile(filepath.Join("testdata", "connectors.agent.yml"))
	require.NoError(t, err, "failed to read service agent config")

	ctx := context.Background()
	kCtx := k8sGetContext(t, info)

	schedulableNodeCount, err := k8sSchedulableNodeCount(ctx, kCtx)
	require.NoError(t, err, "error at getting schedulable node count")
	require.NotZero(t, schedulableNodeCount, "no schedulable Kubernetes nodes found")

	testSteps := []k8sTestStep{
		k8sStepCreateNamespace(),
		k8sStepDeployKustomize("elastic-agent-standalone", k8sKustomizeOverrides{}, func(obj k8s.Object) {
			// update the configmap to only run the connectors input
			switch objWithType := obj.(type) {
			case *corev1.ConfigMap:
				_, ok := objWithType.Data["agent.yml"]
				if ok {
					objWithType.Data["agent.yml"] = string(serviceAgentYAML)
				}
			}
		}),
		k8sStepCheckAgentStatus("app=elastic-agent-standalone", schedulableNodeCount, "elastic-agent-standalone", map[string]bool{
			"connectors-py": true,
		}),
		k8sStepCheckAgentLogs("app=elastic-agent-standalone", "elastic-agent-standalone"),
	}

	testNamespace := kCtx.getNamespace(t)
	for _, step := range testSteps {
		step(t, ctx, kCtx, testNamespace)
	}
}

// k8sStepCheckAgentLogs reads up to 100 connector log lines since pod start
// (requires at least 50 lines), and then validates the log output.
func k8sStepCheckAgentLogs(agentPodLabelSelector string, containerName string) k8sTestStep {
	return func(t *testing.T, ctx context.Context, kCtx k8sContext, namespace string) {
		const maxLogLines = 100
		const minLogLines = 50
		agentPodList := &corev1.PodList{}
		err := kCtx.client.Resources(namespace).List(ctx, agentPodList, func(opt *metav1.ListOptions) {
			opt.LabelSelector = agentPodLabelSelector
		})
		require.NoError(t, err, "failed to list agent pods with selector ", agentPodLabelSelector)
		require.NotEmpty(t, agentPodList.Items, "no agent pods found with selector ", agentPodLabelSelector)

		for _, pod := range agentPodList.Items {
			startTime := pod.Status.StartTime
			var (
				lines   []string
				readErr error
			)
			require.Eventually(t, func() bool {
				logOpts := &corev1.PodLogOptions{
					Container: containerName,
					SinceTime: startTime,
				}
				lines, readErr = k8sReadPodLogLines(ctx, kCtx.clientSet, namespace, pod.Name, logOpts, maxLogLines)
				if readErr != nil {
					return false
				}
				return len(lines) >= minLogLines
			}, 3*time.Minute, 5*time.Second, "expected at least %d log lines for pod %s", minLogLines, pod.Name)
			require.NoError(t, readErr, "error reading logs for pod %s", pod.Name)

			ok, checkErr := connectorLogsHaveSingleLogKey(lines)
			if checkErr != nil {
				t.Fatalf("log validation failed for pod %s: %v", pod.Name, checkErr)
			}
			require.Truef(t, ok, "expected connectors logs in pod %s with single log key", pod.Name)
		}
	}
}

// connectorLogsHaveSingleLogKey scans JSON log lines from the agent pod and
// ensures those entries include a "log.source" key and if the source is "connectors-py-default",
// it also ensures that the log entry includes exactly one "log" key.
func connectorLogsHaveSingleLogKey(lines []string) (bool, error) {
	found := false

	for _, line := range lines {
		if !strings.HasPrefix(line, "{") {
			// ignore non JSON lines. Elastic Agent has a few logs at startup that are not JSON.
			continue
		}

		var entry map[string]any
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			continue
		}

		sourceVal, exists := entry["log.source"]
		if !exists {
			return false, fmt.Errorf("JSON log line does not have a \"log.source\" key: %s", line)
		}
		source, ok := sourceVal.(string)
		if !ok {
			return false, fmt.Errorf("JSON log line has non-string \"log.source\": %s", line)
		}

		if source == "connectors-py-default" {
			found = true
			logKeyCount := strings.Count(line, `"log":`)
			if logKeyCount != 1 {
				return false, fmt.Errorf("expected exactly one \"log\" key, got %d: %s", logKeyCount, line)
			}
		}
	}

	return found, nil
}
