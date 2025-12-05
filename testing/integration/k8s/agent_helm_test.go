// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration

package k8s

import (
	"context"
	"fmt"
	"regexp"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"helm.sh/helm/v3/pkg/cli/values"

	"github.com/elastic/elastic-agent/pkg/testing/define"
)

func TestKubernetesAgentHelmRotatedLogs(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Stack: &define.Stack{},
		Local: false,
		Sudo:  false,
		OS: []define.OS{
			// only test the basic and the wolfi container
			{Type: define.Kubernetes, DockerVariant: "basic"},
			{Type: define.Kubernetes, DockerVariant: "wolfi"},
		},
		Group: define.Kubernetes,
	})

	containerRegex, err := regexp.Compile(`^/var/log/containers/.*flog.*\.log$`)
	require.NoError(t, err, "failed to compile container log regex")
	plainRegex, err := regexp.Compile(`\d+\.log\.\d{8}-\d{6}$`)
	require.NoError(t, err, "failed to compile rotated plain log regex")
	gzRegex, err := regexp.Compile(`\d+\.log\.\d{8}-\d{6}\.gz$`)
	require.NoError(t, err, "failed to compile rotated gzip regex")

	kCtx := k8sGetContext(t, info)

	defaultValues := values.Options{
		ValueFiles: []string{"../../../deploy/helm/elastic-agent/values.yaml"},
		Values: []string{
			fmt.Sprintf("agent.image.repository=%s", kCtx.agentImageRepo),
			fmt.Sprintf("agent.image.tag=%s", kCtx.agentImageTag),

			"outputs.default.type=ESPlainAuthAPI",
			fmt.Sprintf("outputs.default.url=%s", kCtx.esHost),
			fmt.Sprintf("outputs.default.api_key=%s", kCtx.esAPIKey),

			// Enable k8s and container logs
			"kubernetes.enabled=true",
			"kubernetes.containers.logs.enabled=true",

			// Disable others
			"kubernetes.state.enabled=false",
			"kubernetes.metrics.enabled=false",
			"kubernetes.apiserver.enabled=false",
			"kubernetes.proxy.enabled=false",
			"kubernetes.scheduler.enabled=false",
			"kubernetes.controller_manager.enabled=false",
			"kubernetes.containers.metrics.enabled=false",
			"kubernetes.containers.state.enabled=false",
			"kubernetes.containers.audit_logs.enabled=false",
			"kubernetes.pods.enabled=false",
		},
	}

	steps := []k8sTestStep{
		k8sStepCreateNamespace(),

		// 1st - deploy flog
		func(t *testing.T, ctx context.Context, kCtx k8sContext, namespace string) {
			k8sStepDeployApp("flog.yaml")(t, ctx, kCtx, namespace)
		},

		// 2nd - deploy the agent without rotated logs enabled
		k8sStepHelmDeployWithValueOptions(AgentHelmChartPath, "elastic-agent",
			defaultValues,
		),

		// 3rd - check that the agent pod is running
		k8sStepCheckRunningPods(
			"name=agent-pernode-elastic-agent",
			1, "agent"),

		// 4th - verify logs are ingested from `/var/log/containers/`
		k8sStepCheckLogFilesIngested(info,
			"logs", "kubernetes.container_logs", "default", "/var/log/containers/*flog*.log",
			expectedLogFile{regex: containerRegex,
				description: "container log (" + containerRegex.String() + ")"},
		),

		// 5th - upgrade the agent to enable rotated logs
		k8sStepHelmUpgrade(AgentHelmChartPath, "elastic-agent",
			values.Options{
				ValueFiles: defaultValues.ValueFiles,
				Values: append(defaultValues.Values,
					"kubernetes.containers.logs.rotated_logs=true"),
			}),

		// 6th - check that the agent pod is running
		k8sStepCheckRunningPods(
			"name=agent-pernode-elastic-agent",
			1, "agent"),

		// 7th - verify rotated logs are ingested
		k8sStepCheckLogFilesIngested(info,
			"logs", "kubernetes.container_logs", "default", "/var/log/pods/*flog*",
			expectedLogFile{regex: plainRegex,
				description: "plain text rotated log (" + plainRegex.String() + ")"},
			expectedLogFile{regex: gzRegex,
				description: "gzipped rotated log (" + gzRegex.String() + ")"},
		),
	}

	ctx := context.Background()
	testNamespace := kCtx.getNamespace(t)

	for _, step := range steps {
		step(t, ctx, kCtx, testNamespace)
	}
}

// expectedLogFile represents a log file pattern to verify in Elasticsearch
type expectedLogFile struct {
	regex       *regexp.Regexp
	description string
}

// k8sStepCheckLogFilesIngested creates a test step that verifies rotated logs are ingested
// by querying Elasticsearch and checking for files matching the provided regex patterns.
func k8sStepCheckLogFilesIngested(
	info *define.Info,
	dsType, dataset, datastreamNamespace, wildcardPath string,
	expectedFiles ...expectedLogFile,
) k8sTestStep {
	return func(t *testing.T, ctx context.Context, kCtx k8sContext, namespace string) {
		require.EventuallyWithT(t, func(collectT *assert.CollectT) {
			query := map[string]any{
				"size":    0,
				"_source": []string{"message"},
				"query": map[string]any{
					"bool": map[string]any{
						"filter": []any{
							map[string]any{
								"term": map[string]any{
									"data_stream.dataset": dataset,
								},
							},
							map[string]any{
								"term": map[string]any{
									"data_stream.namespace": datastreamNamespace,
								},
							},
							map[string]any{
								"term": map[string]any{
									"data_stream.type": dsType,
								},
							},
							map[string]any{
								"wildcard": map[string]any{
									"log.file.path": map[string]any{
										"value": wildcardPath,
									},
								},
							},
						},
					},
				},
				"aggs": map[string]any{
					"files_count": map[string]any{
						"terms": map[string]any{
							"field": "log.file.path",
						},
					},
				},
			}

			resp, err := PerformQuery(
				ctx, query, fmt.Sprintf(".ds-%s*", dsType), info.ESClient)
			require.NoError(collectT, err,
				"failed to query %s datastream",
				fmt.Sprintf("%s-%s-%s", dsType, dataset, datastreamNamespace))

			// Track which expected files were found
			found := make([]bool, len(expectedFiles))
			var files []string

			for _, bucket := range resp.Aggregations.FilesCount.Buckets {
				files = append(files, bucket.Key)
				for i, expected := range expectedFiles {
					if expected.regex.MatchString(bucket.Key) {
						found[i] = true
					}
				}
			}

			// Assert all expected files were found
			for i, expected := range expectedFiles {
				assert.True(collectT, found[i],
					"expected to find %s, found only: %v",
					expected.description, files)
			}
		}, 3*time.Minute, 10*time.Second, fmt.Sprintf("no documets found on datastream %s",
			fmt.Sprintf("%s-%s-%s", dsType, dataset, datastreamNamespace)))
	}
}
