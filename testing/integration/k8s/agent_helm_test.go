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

func TestAgentKubeStackHelm(t *testing.T) {
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

	plainRegex, err := regexp.Compile(`\d+\.log\.\d{8}-\d{6}$`)
	require.NoError(t, err, "failed to compile regex")
	gzRegex, err := regexp.Compile(`\d+\.log\.\d{8}-\d{6}\.gz$`)
	require.NoError(t, err, "failed to compile regex")

	kCtx := k8sGetContext(t, info)

	steps := []k8sTestStep{
		k8sStepCreateNamespace(),

		// 1st - deploy flog so logs can be rotated before filebeat starts
		// ingesting them
		func(t *testing.T, ctx context.Context, kCtx k8sContext, namespace string) {
			k8sStepDeployApp("flog.yaml")(t, ctx, kCtx, namespace)
			time.Sleep(30 * time.Second) // wait for logs to be rotated
		},

		// 2nd - deploy the agent
		k8sStepHelmDeployWithValueOptions(AgentHelmChartPath, "elastic-agent",
			values.Options{
				ValueFiles: []string{"../../../deploy/helm/elastic-agent/values.yaml"},
				Values: []string{
					fmt.Sprintf("agent.image.repository=%s", kCtx.agentImageRepo),
					fmt.Sprintf("agent.image.tag=%s", kCtx.agentImageTag),

					"outputs.default.type=ESPlainAuthAPI",
					fmt.Sprintf("outputs.default.url=%s", kCtx.esHost),
					fmt.Sprintf("outputs.default.api_key=%s", kCtx.esAPIKey),

					"kubernetes.enabled=true",
					"kubernetes.containers.logs.enabled=true",
					"kubernetes.containers.logs.rotated_logs=true",

					// Disable everything else
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
			},
		),

		// 3rd - check that the agent pod is running
		k8sStepCheckRunningPods(
			"name=agent-pernode-elastic-agent",
			1, "agent"),

		// 4th - verify rotated logs are ingested
		func(t *testing.T, ctx context.Context, kCtx k8sContext, namespace string) {
			dsType := "logs"
			dataset := "kubernetes.container_logs"
			datastreamNamespace := "default"

			require.EventuallyWithT(t, func(t *assert.CollectT) {
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
											"value": "/var/log/pods/*flog*",
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
				require.NoError(t, err,
					"failed to query %s datastream",
					fmt.Sprintf("%s-%s-%s", dsType, dataset, datastreamNamespace))

				var foundPlain, foundGz bool
				var files []string
				for _, bucket := range resp.Aggregations.FilesCount.Buckets {
					files = append(files, bucket.Key)
					if plainRegex.MatchString(bucket.Key) {
						foundPlain = true
						continue
					}
					if gzRegex.MatchString(bucket.Key) {
						foundGz = true
						continue
					}
				}

				assert.True(t, foundPlain,
					"expected to find plain text rotated log, found only: %v",
					files)
				assert.True(t, foundGz,
					"expected to find gzipped rotated logs, found only: %v",
					files)
			}, 3*time.Minute, 10*time.Second, fmt.Sprintf("no documets found on datastream %s",
				fmt.Sprintf("%s-%s-%s", dsType, dataset, datastreamNamespace)))
		},
	}

	ctx := context.Background()
	testNamespace := kCtx.getNamespace(t)

	for _, step := range steps {
		step(t, ctx, kCtx, testNamespace)
	}
}
