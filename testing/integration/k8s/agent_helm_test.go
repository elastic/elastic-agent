// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration

package k8s

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"helm.sh/helm/v4/pkg/cli/values"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

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
		k8sStepRecordLogsCheckpoint(info, checkpoint),
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
		k8sStepRecordLogsCheckpoint(info, checkpoint),
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
	//
	// A unique log marker is written after the agent is running and must appear
	// in Elasticsearch before the timestamp checkpoint is set. This guarantees
	// the agent is actively indexing at the moment the checkpoint is recorded,
	// so the subsequent flog checks cannot pass on a stale pre-upgrade document
	// that was produced by the old agent but indexed only after the upgrade.
	checkpoint := &logsCheckpoint{}
	marker := &logMarker{}
	checkIngested := func() []k8sTestStep {
		return []k8sTestStep{
			k8sStepCheckRunningPods("name=agent-pernode-elastic-agent", 1, "agent"),
			k8sStepDeployLogMarker(marker),
			k8sStepWaitForLogMarker(info, marker),
			k8sStepRecordLogsCheckpoint(info, checkpoint),
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

// logsCheckpoint is the @timestamp (epoch millis) of the latest flog log
// document in Elasticsearch at the time it was recorded. Checks using it only
// consider documents newer than that.
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

// logMarker is a unique string written to a short-lived pod's stdout after
// each helm deployment step. k8sStepWaitForLogMarker blocks until the marker
// appears in Elasticsearch, proving the running agent is actively indexing
// container logs from the test namespace before the timestamp checkpoint is set.
type logMarker struct {
	id string
}

// k8sStepDeployLogMarker creates a one-shot pod that writes a unique marker
// string to stdout and waits for the pod to succeed.
func k8sStepDeployLogMarker(marker *logMarker) k8sTestStep {
	return func(t *testing.T, ctx context.Context, kCtx k8sContext, namespace string) {
		uid, err := uuid.NewV4()
		require.NoError(t, err, "failed to generate log marker UUID")
		// Strip dashes so the marker is a single word, directly findable with match_phrase.
		marker.id = "elasticagentmarker" + strings.ReplaceAll(uid.String(), "-", "")

		podName := "log-marker-" + uid.String()[:8]
		pod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      podName,
				Namespace: namespace,
			},
			Spec: corev1.PodSpec{
				RestartPolicy: corev1.RestartPolicyNever,
				Containers: []corev1.Container{
					{
						Name:    "marker",
						Image:   "busybox",
						Command: []string{"sh", "-c", "echo " + marker.id},
					},
				},
			},
		}

		_, err = kCtx.clientSet.CoreV1().Pods(namespace).Create(ctx, pod, metav1.CreateOptions{})
		require.NoError(t, err, "failed to create log marker pod")

		require.EventuallyWithT(t, func(ct *assert.CollectT) {
			p, err := kCtx.clientSet.CoreV1().Pods(namespace).Get(ctx, podName, metav1.GetOptions{})
			require.NoError(ct, err)
			assert.Equal(ct, corev1.PodSucceeded, p.Status.Phase,
				"marker pod %s phase: %s", podName, p.Status.Phase)
		}, 2*time.Minute, 5*time.Second, "log marker pod did not succeed")

		t.Logf("log marker deployed: %s", marker.id)
	}
}

// k8sStepWaitForLogMarker blocks until the marker string written by
// k8sStepDeployLogMarker appears in Elasticsearch with the expected
// kubernetes.namespace, proving the agent is forwarding logs from the namespace.
func k8sStepWaitForLogMarker(info *define.Info, marker *logMarker) k8sTestStep {
	return func(t *testing.T, ctx context.Context, kCtx k8sContext, namespace string) {
		require.EventuallyWithT(t, func(ct *assert.CollectT) {
			query := map[string]any{
				"size": 0,
				"query": map[string]any{
					"bool": map[string]any{
						"filter": []any{
							map[string]any{"term": map[string]any{
								"data_stream.dataset": "kubernetes.container_logs",
							}},
							map[string]any{"term": map[string]any{
								"kubernetes.namespace": namespace,
							}},
							map[string]any{"match_phrase": map[string]any{
								"message": marker.id,
							}},
						},
					},
				},
			}
			resp, err := PerformQuery(ctx, query, ".ds-logs*", info.ESClient)
			require.NoError(ct, err, "failed to query for log marker")
			assert.Positive(ct, resp.Hits.Total.Value,
				"marker %s not yet in Elasticsearch", marker.id)
		}, 3*time.Minute, 10*time.Second, "log marker never appeared in Elasticsearch")
		t.Logf("log marker confirmed in Elasticsearch: %s", marker.id)
	}
}

// k8sStepRecordLogsCheckpoint records in checkpoint the @timestamp of the
// latest flog container log document. Run it once the agent under test is
// running, so that documents sent by a previous agent are older than the
// checkpoint. The checkpoint comes from Elasticsearch so it doesn't depend on
// the clock of the test runner.
func k8sStepRecordLogsCheckpoint(info *define.Info, checkpoint *logsCheckpoint) k8sTestStep {
	return func(t *testing.T, ctx context.Context, kCtx k8sContext, namespace string) {
		query := map[string]any{
			"size": 0,
			"query": map[string]any{
				"bool": map[string]any{
					"filter": []any{
						map[string]any{"term": map[string]any{"data_stream.dataset": "kubernetes.container_logs"}},
						map[string]any{"term": map[string]any{"data_stream.type": "logs"}},
						map[string]any{"wildcard": map[string]any{"log.file.path": map[string]any{"value": "*flog*"}}},
					},
				},
			},
			"aggs": map[string]any{
				"max_timestamp": map[string]any{"max": map[string]any{"field": "@timestamp"}},
			},
		}

		resp, err := PerformQuery(ctx, query, ".ds-logs*", info.ESClient)
		require.NoError(t, err, "failed to query the latest container log timestamp")
		checkpoint.epochMillis = int64(resp.Aggregations.MaxTimestamp.Value)
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
