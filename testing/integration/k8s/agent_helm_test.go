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
	"helm.sh/helm/v4/pkg/cli/values"

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

	rotatedExpected := []expectedLogFile{
		{
			regex:       plainRegex,
			description: "plain text rotated log (" + plainRegex.String() + ")",
		},
	}

	// Kind compresses rotated log files.
	if !kCtx.openshift {
		rotatedExpected = append(rotatedExpected, expectedLogFile{
			regex:       gzRegex,
			description: "gzipped rotated log (" + gzRegex.String() + ")",
		})
	}

	defaultValues := helmContainerLogsValues(kCtx)
	checkpoint := &logsCheckpoint{}

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

		// 4th - verify new logs are ingested from `/var/log/containers/` with kubernetes metadata
		k8sStepRecordLogsCheckpoint(checkpoint),
		k8sStepCheckLogFilesIngested(info,
			"logs", "kubernetes.container_logs", "default", "/var/log/containers/*flog*.log", checkpoint,
			expectedLogFile{regex: containerRegex,
				description: "container log (" + containerRegex.String() + ")"},
		),
		k8sStepCheckContainerLogsMetadata(info, "/var/log/containers/*flog*.log", checkpoint),

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

		// 7th - verify new rotated logs are ingested with kubernetes metadata
		k8sStepRecordLogsCheckpoint(checkpoint),
		k8sStepCheckLogFilesIngested(info,
			"logs", "kubernetes.container_logs", "default", "/var/log/pods/*flog*", checkpoint,
			rotatedExpected...,
		),
		k8sStepCheckContainerLogsMetadata(info, "/var/log/pods/*flog*", checkpoint),
	}

	ctx := context.Background() //nolint:forbidigo // ctx is captured by t.Cleanup in step functions; must outlive the test
	testNamespace := kCtx.getNamespace(t)

	for _, step := range steps {
		step(t, ctx, kCtx, testNamespace)
	}
}

// helmContainerLogsValues returns the Helm values that enable only the
// Kubernetes container logs stream.
func helmContainerLogsValues(kCtx k8sContext) values.Options {
	return values.Options{
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
}

// TestKubernetesAgentHelmSingleContainerLogsInput verifies that container logs
// are ingested, enriched with Kubernetes metadata, in both modes of
// `kubernetes.containers.logs.single_input` (the default, true, and false), and
// that switching between the modes keeps the logs flowing.
func TestKubernetesAgentHelmSingleContainerLogsInput(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Stack: &define.Stack{},
		Local: false,
		Sudo:  false,
		OS: []define.OS{
			{Type: define.Kubernetes, DockerVariant: "basic"},
		},
		Group: define.Kubernetes,
	})

	containerRegex, err := regexp.Compile(`^/var/log/containers/.*flog.*\.log$`)
	require.NoError(t, err, "failed to compile container log regex")
	containerFile := expectedLogFile{
		regex:       containerRegex,
		description: "container log (" + containerRegex.String() + ")",
	}

	kCtx := k8sGetContext(t, info)

	// single_input is intentionally not set so the chart default is tested.
	defaultValues := helmContainerLogsValues(kCtx)
	perContainerValues := values.Options{
		ValueFiles: defaultValues.ValueFiles,
		Values: append(append([]string{}, defaultValues.Values...),
			"kubernetes.containers.logs.single_input=false"),
	}
	singleInputValues := values.Options{
		ValueFiles: defaultValues.ValueFiles,
		Values: append(append([]string{}, defaultValues.Values...),
			"kubernetes.containers.logs.single_input=true"),
	}

	// checkIngested verifies that logs produced after the previous deployment
	// step are ingested; documents from earlier steps are ignored so a mode
	// switch that stops the ingestion can't pass on stale documents.
	checkpoint := &logsCheckpoint{}
	checkIngested := func() []k8sTestStep {
		return []k8sTestStep{
			k8sStepCheckRunningPods("name=agent-pernode-elastic-agent", 1, "agent"),
			k8sStepRecordLogsCheckpoint(checkpoint),
			k8sStepCheckLogFilesIngested(info,
				"logs", "kubernetes.container_logs", "default", "/var/log/containers/*flog*.log", checkpoint,
				containerFile),
			k8sStepCheckContainerLogsMetadata(info, "/var/log/containers/*flog*.log", checkpoint),
		}
	}

	steps := []k8sTestStep{
		k8sStepCreateNamespace(),
		func(t *testing.T, ctx context.Context, kCtx k8sContext, namespace string) {
			k8sStepDeployApp("flog.yaml")(t, ctx, kCtx, namespace)
		},

		// default: single input
		k8sStepHelmDeployWithValueOptions(AgentHelmChartPath, "elastic-agent", defaultValues),
	}
	steps = append(steps, checkIngested()...)

	// opt out: one input per container
	steps = append(steps, k8sStepHelmUpgrade(AgentHelmChartPath, "elastic-agent", perContainerValues))
	steps = append(steps, checkIngested()...)

	// back to the single input, taking over the per-container inputs' state
	steps = append(steps, k8sStepHelmUpgrade(AgentHelmChartPath, "elastic-agent", singleInputValues))
	steps = append(steps, checkIngested()...)

	ctx := context.Background() //nolint:forbidigo // ctx is captured by t.Cleanup in step functions; must outlive the test
	testNamespace := kCtx.getNamespace(t)

	for _, step := range steps {
		step(t, ctx, kCtx, testNamespace)
	}
}

// logsCheckpoint is the wall-clock time (epoch millis) at which it was
// recorded. Checks using it only consider documents with @timestamp strictly
// greater than the checkpoint, which excludes any log line produced before the
// checkpoint regardless of when Elasticsearch indexes it.
type logsCheckpoint struct {
	epochMillis int64
}

// filter returns the Elasticsearch filters restricting a query to documents
// newer than the checkpoint. It is empty when no checkpoint was recorded.
func (c *logsCheckpoint) filter() []any {
	if c == nil || c.epochMillis == 0 {
		return nil
	}
	return []any{
		map[string]any{"range": map[string]any{"@timestamp": map[string]any{
			"gt":     c.epochMillis,
			"format": "epoch_millis",
		}}},
	}
}

// k8sStepRecordLogsCheckpoint records the current wall-clock time as the
// checkpoint. Subsequent checks only consider log documents with @timestamp
// strictly greater than this value. Because flog generates timestamps in real
// time, any log line produced before this moment has @timestamp ≤ checkpoint
// and is filtered out — including lines that were produced just before the
// upgrade but had not yet been indexed when the checkpoint was set.
func k8sStepRecordLogsCheckpoint(checkpoint *logsCheckpoint) k8sTestStep {
	return func(t *testing.T, _ context.Context, _ k8sContext, _ string) {
		checkpoint.epochMillis = time.Now().UnixMilli()
		t.Logf("container logs checkpoint: %d", checkpoint.epochMillis)
	}
}

// k8sStepCheckContainerLogsMetadata verifies that the flog container logs
// ingested from wildcardPath after the checkpoint are enriched with
// Kubernetes metadata.
func k8sStepCheckContainerLogsMetadata(info *define.Info, wildcardPath string, checkpoint *logsCheckpoint) k8sTestStep {
	return func(t *testing.T, ctx context.Context, kCtx k8sContext, namespace string) {
		require.EventuallyWithT(t, func(collectT *assert.CollectT) {
			query := map[string]any{
				"size": 0,
				"query": map[string]any{
					"bool": map[string]any{
						"filter": append([]any{
							map[string]any{"term": map[string]any{"data_stream.dataset": "kubernetes.container_logs"}},
							map[string]any{"term": map[string]any{"data_stream.type": "logs"}},
							map[string]any{"wildcard": map[string]any{"log.file.path": map[string]any{"value": wildcardPath}}},
							map[string]any{"wildcard": map[string]any{"kubernetes.pod.name": map[string]any{"value": "flog-log-generator*"}}},
							map[string]any{"term": map[string]any{"kubernetes.container.name": "flog-unstructured-cont-rot"}},
							map[string]any{"term": map[string]any{"kubernetes.namespace": namespace}},
						}, checkpoint.filter()...),
					},
				},
			}

			resp, err := PerformQuery(ctx, query, ".ds-logs*", info.ESClient)
			require.NoError(collectT, err, "failed to query container logs metadata")
			assert.Positive(collectT, resp.Hits.Total.Value,
				"no flog container logs from %s enriched with kubernetes metadata", wildcardPath)
		}, 3*time.Minute, 10*time.Second, "no container logs with kubernetes metadata found")
	}
}

// expectedLogFile represents a log file pattern to verify in Elasticsearch
type expectedLogFile struct {
	regex       *regexp.Regexp
	description string
}

// k8sStepCheckLogFilesIngested creates a test step that verifies logs are ingested
// (only the ones newer than the checkpoint, when set) by querying Elasticsearch and checking for files matching the provided regex patterns.
func k8sStepCheckLogFilesIngested(
	info *define.Info,
	dsType, dataset, datastreamNamespace, wildcardPath string,
	checkpoint *logsCheckpoint,
	expectedFiles ...expectedLogFile,
) k8sTestStep {
	return func(t *testing.T, ctx context.Context, kCtx k8sContext, namespace string) {
		require.EventuallyWithT(t, func(collectT *assert.CollectT) {
			query := map[string]any{
				"size":    0,
				"_source": []string{"message"},
				"query": map[string]any{
					"bool": map[string]any{
						"filter": append([]any{
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
						}, checkpoint.filter()...),
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
