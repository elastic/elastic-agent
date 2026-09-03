// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration

package k8s

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"helm.sh/helm/v3/pkg/cli/values"
	appsv1 "k8s.io/api/apps/v1"
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

	// baseValues are the Helm values shared by both test cases.
	baseValues := values.Options{
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

	// testCases exercises both the native filelog receiver path (default, feature ON)
	// and the legacy filebeatreceiver path (feature OFF via emergency env-var escape hatch).
	// Both must produce ECS-compatible documents with equivalent field coverage.
	testCases := []struct {
		name      string
		helmExtra []string // appended to baseValues.Values
	}{
		{
			// Feature ON is the default — no Helm override needed.
			name: "native_filelog_on",
		},
		{
			// Feature OFF: set ELASTIC_AGENT_KUBERNETES_FILELOG=false via the DaemonSet
			// extraEnvs. The preset lives at agent.presets.perNode (not
			// kubernetes.presets.perNode). We also carry over ELASTIC_NETINFO (index 0)
			// because --set replaces the whole array from the values file.
			name: "native_filelog_off",
			helmExtra: []string{
				"agent.presets.perNode.extraEnvs[0].name=ELASTIC_NETINFO",
				"agent.presets.perNode.extraEnvs[0].value=false",
				"agent.presets.perNode.extraEnvs[1].name=ELASTIC_AGENT_KUBERNETES_FILELOG",
				"agent.presets.perNode.extraEnvs[1].value=false",
			},
		},
	}

	type testCaseResult struct {
		resources    resourceSample
		churnLatency time.Duration
	}
	results := make(map[string]testCaseResult)

	for _, tc := range testCases {
		tc := tc
		result := testCaseResult{}

		sampler, startSamplerStep := k8sStepStartResourceSampler(&result.resources, "name=agent-pernode-elastic-agent", "agent")

		t.Run(tc.name, func(t *testing.T) {
			deployValues := values.Options{
				ValueFiles: baseValues.ValueFiles,
				Values:     append(append([]string{}, baseValues.Values...), tc.helmExtra...),
			}
			// Upgrade must also carry the feature-flag env var so the restarted
			// pods don't revert to the default.
			upgradeValues := values.Options{
				ValueFiles: deployValues.ValueFiles,
				Values:     append(append([]string{}, deployValues.Values...), "kubernetes.containers.logs.rotated_logs=true"),
			}

			steps := []k8sTestStep{
				k8sStepCreateNamespace(),

				// 1 - deploy flog
				func(t *testing.T, ctx context.Context, kCtx k8sContext, namespace string) {
					k8sStepDeployApp("flog.yaml")(t, ctx, kCtx, namespace)
				},

				// 2 - deploy the agent without rotated logs enabled
				k8sStepHelmDeployWithValueOptions(AgentHelmChartPath, "elastic-agent", deployValues),

				// 3 - check that the agent pod is running
				k8sStepCheckRunningPods("name=agent-pernode-elastic-agent", 1, "agent"),

				// 4 - start resource sampler BEFORE ingestion so we capture active load
				startSamplerStep,

				// 5 - verify logs are ingested from `/var/log/containers/`; agent is
				// actively reading and shipping during this step — that's when we sample.
				// The step filters on kubernetes.namespace (the test namespace) so the
				// check only passes for documents from THIS run, not leftover docs from
				// a previous run sharing the same ES cluster.
				k8sStepCheckLogFilesIngested(info,
					"logs", "kubernetes.container_logs", "default", "/var/log/containers/*flog*.log",
					expectedLogFile{
						regex:       containerRegex,
						description: "container log (" + containerRegex.String() + ")",
					},
				),

				// 6 - stop sampler now that initial ingestion is confirmed
				k8sStepStopResourceSampler(sampler, &result.resources),

				// 7 - validate ECS fields are present
				k8sStepCheckK8sECSFieldsIngested(info, "kubernetes.container_logs"),

				// 8 - deploy a brand-new flog deployment (previously unseen label) and
				// measure how long until its logs appear in ES — this forces the filebeat
				// dynamic provider to detect a new pod type and reconfigure, while native
				// filelog picks it up immediately via the existing glob pattern.
				k8sStepDeployNewFlogAndMeasureChurn(info, &result.churnLatency),

				// 9 - upgrade the agent to enable rotated logs
				k8sStepHelmUpgrade(AgentHelmChartPath, "elastic-agent", upgradeValues),

				// 10 - check that the agent pod is running
				k8sStepCheckRunningPods("name=agent-pernode-elastic-agent", 1, "agent"),

				// 11 - verify rotated logs are ingested
				k8sStepCheckLogFilesIngested(info,
					"logs", "kubernetes.container_logs", "default", "/var/log/pods/*flog*",
					expectedLogFile{
						regex:       plainRegex,
						description: "plain text rotated log (" + plainRegex.String() + ")",
					},
					expectedLogFile{
						regex:       gzRegex,
						description: "gzipped rotated log (" + gzRegex.String() + ")",
					},
				),
			}

			ctx := context.Background() //nolint:forbidigo // ctx is captured by t.Cleanup in step functions; must outlive the test
			testNamespace := kCtx.getNamespace(t)

			for _, step := range steps {
				step(t, ctx, kCtx, testNamespace)
			}
		})

		results[tc.name] = result
	}

	// Print a side-by-side comparison after both sub-tests complete.
	on, hasOn := results["native_filelog_on"]
	off, hasOff := results["native_filelog_off"]
	if hasOn && hasOff {
		t.Logf("=== Agent resource usage (sampled during active ingestion) ===")
		t.Logf("%-22s  %12s  %12s", "Mode", "CPU (mCPU)", "Mem (MiB)")
		t.Logf("%-22s  %12.2f  %12.1f", "native_filelog_on", on.resources.cpuMilliCores, on.resources.memMiB)
		t.Logf("%-22s  %12.2f  %12.1f", "native_filelog_off", off.resources.cpuMilliCores, off.resources.memMiB)
		if off.resources.cpuMilliCores > 0 {
			t.Logf("CPU delta (on vs off): %+.1f%%", (on.resources.cpuMilliCores-off.resources.cpuMilliCores)/off.resources.cpuMilliCores*100)
		}
		if off.resources.memMiB > 0 {
			t.Logf("Mem delta (on vs off): %+.1f%%", (on.resources.memMiB-off.resources.memMiB)/off.resources.memMiB*100)
		}

		if on.churnLatency > 0 || off.churnLatency > 0 {
			t.Logf("=== New-pod log ingestion latency (pod scale → first ES doc) ===")
			t.Logf("%-22s  %12s", "Mode", "Latency")
			t.Logf("%-22s  %12s", "native_filelog_on", on.churnLatency.Round(time.Millisecond))
			t.Logf("%-22s  %12s", "native_filelog_off", off.churnLatency.Round(time.Millisecond))
			if off.churnLatency > 0 && on.churnLatency > 0 {
				t.Logf("Churn latency improvement: %.1fx faster (on vs off)", float64(off.churnLatency)/float64(on.churnLatency))
			}
		}
	}
}

// expectedLogFile represents a log file pattern to verify in Elasticsearch
type expectedLogFile struct {
	regex       *regexp.Regexp
	description string
}

// k8sStepCheckLogFilesIngested creates a test step that verifies logs are ingested
// by querying Elasticsearch and checking for files matching the provided regex patterns.
// The query filters on kubernetes.namespace (= the test namespace passed to the step)
// so results only match documents produced by THIS run, not leftover docs from prior runs.
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
							// Scope to this test run's namespace by matching the
							// namespace embedded in the log file path. Container
							// logs: /var/log/containers/<pod>_<ns>_<cont>-<id>.log
							// Pod logs: /var/log/pods/<ns>_<pod>_<uid>/...
							// We use log.file.path (always a keyword) rather than
							// kubernetes.namespace, which may auto-map as text on a
							// fresh cluster before index templates are applied.
							map[string]any{
								"wildcard": map[string]any{
									"log.file.path": map[string]any{
										"value": fmt.Sprintf("*%s*", namespace),
									},
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
		}, 10*time.Minute, 10*time.Second, fmt.Sprintf("no documets found on datastream %s",
			fmt.Sprintf("%s-%s-%s", dsType, dataset, datastreamNamespace)))
	}
}

// k8sStepCheckK8sECSFieldsIngested verifies that core Kubernetes ECS fields are present
// in at least one ingested document in the given dataset. The check uses Elasticsearch
// exists filters so the query only returns documents that have ALL listed fields set;
// a non-zero hit count proves complete field coverage.
//
// The same set of fields is expected from both the native filelog receiver path
// (feature ON) and the legacy filebeatreceiver path (feature OFF), ensuring
// transparent field parity across migration modes.
func k8sStepCheckK8sECSFieldsIngested(info *define.Info, dataset string) k8sTestStep {
	return func(t *testing.T, ctx context.Context, kCtx k8sContext, namespace string) {
		// Fields that must be present in every kubernetes.container_logs document,
		// regardless of which ingestion path (native filelog or filebeatreceiver) was used.
		requiredFields := []string{
			// Core Kubernetes metadata — from k8sattributes (native) or beats dynamic provider (legacy)
			"kubernetes.pod.name",
			"kubernetes.namespace",
			"kubernetes.container.name",
			"kubernetes.node.name",
			// Container metadata — from k8sattributes API lookup
			"container.id",
			"container.image.name",
			// Pod labels — k8sattributes wildcard extraction (native) or beats add_fields (legacy)
			// flog.yaml sets app=flog-log-generator on its pods, so this label must appear.
			"kubernetes.labels.app",
			// Log provenance
			"log.file.path",
			"message",
			// ECS / event classification
			"event.dataset",
			// Agent identity
			"agent.type",
		}

		filters := []any{
			map[string]any{"term": map[string]any{"data_stream.dataset": dataset}},
		}
		for _, field := range requiredFields {
			filters = append(filters, map[string]any{
				"exists": map[string]any{"field": field},
			})
		}

		query := map[string]any{
			"size": 1,
			"query": map[string]any{
				"bool": map[string]any{
					"filter": filters,
				},
			},
		}

		require.EventuallyWithT(t, func(collectT *assert.CollectT) {
			resp, err := PerformQuery(ctx, query, ".ds-logs*", info.ESClient)
			require.NoError(collectT, err, "failed to query for ECS fields in dataset %s", dataset)
			assert.Greater(collectT, resp.Hits.Total.Value, 0,
				"expected at least one document in %s with all required ECS fields present: %v",
				dataset, requiredFields)
		}, 10*time.Minute, 10*time.Second,
			"required ECS fields never appeared together in dataset %s", dataset)
	}
}

// k8sStepDeployNewFlogAndMeasureChurn creates a brand-new flog deployment with a
// previously unseen label and measures how long it takes until its logs appear in ES.
//
// Using a new deployment (not just scaling an existing one) is important: the filebeat
// dynamic provider must detect the new pod label, generate a new input config, and
// reload filebeat before it starts collecting. The native OTel filelog receiver already
// tails /var/log/containers/*.log, so it picks up the new pod's log file the moment
// the container starts writing — no reconfiguration needed.
func k8sStepDeployNewFlogAndMeasureChurn(info *define.Info, dst *time.Duration) k8sTestStep {
	return func(t *testing.T, ctx context.Context, kCtx k8sContext, namespace string) {
		const churnName = "flog-churn-test"
		replicas := int32(1)

		deploy := &appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{Name: churnName, Namespace: namespace},
			Spec: appsv1.DeploymentSpec{
				Replicas: &replicas,
				Selector: &metav1.LabelSelector{
					MatchLabels: map[string]string{"app": churnName},
				},
				Template: corev1.PodTemplateSpec{
					ObjectMeta: metav1.ObjectMeta{
						Labels: map[string]string{"app": churnName},
					},
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{{
							Name:  "flog",
							Image: "mingrammer/flog",
							Args:  []string{"-t", "stdout", "-d", "1us", "-l"},
						}},
					},
				},
			},
		}

		_, err := kCtx.clientSet.AppsV1().Deployments(namespace).Create(ctx, deploy, metav1.CreateOptions{})
		require.NoError(t, err, "create churn deployment %s", churnName)

		deployTime := time.Now()
		t.Logf("pod churn: created new deployment %s", churnName)

		// Clean up the churn deployment after the step regardless of outcome.
		t.Cleanup(func() {
			_ = kCtx.clientSet.AppsV1().Deployments(namespace).Delete(
				ctx, churnName, metav1.DeleteOptions{})
		})

		// Wait for the pod to be Running.
		var newPodName string
		require.EventuallyWithT(t, func(ct *assert.CollectT) {
			pods, err := kCtx.clientSet.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{
				LabelSelector: "app=" + churnName,
			})
			if !assert.NoError(ct, err, "list churn pods") {
				return
			}
			for _, pod := range pods.Items {
				if pod.Status.Phase == corev1.PodRunning {
					newPodName = pod.Name
					return
				}
			}
			assert.Fail(ct, "churn pod not Running yet")
		}, 60*time.Second, 2*time.Second, "churn pod never became Running")

		podReadyTime := time.Now()
		t.Logf("pod churn: pod %s Running after %s",
			newPodName, podReadyTime.Sub(deployTime).Round(time.Millisecond))

		// Wait for ES to have at least one document from the new pod.
		require.EventuallyWithT(t, func(ct *assert.CollectT) {
			query := map[string]any{
				"size": 1,
				"query": map[string]any{
					"bool": map[string]any{
						"filter": []any{
							map[string]any{"term": map[string]any{"data_stream.dataset": "kubernetes.container_logs"}},
							map[string]any{"term": map[string]any{"kubernetes.namespace": namespace}},
							map[string]any{"term": map[string]any{"kubernetes.pod.name": newPodName}},
						},
					},
				},
			}
			resp, err := PerformQuery(ctx, query, ".ds-logs*", info.ESClient)
			assert.NoError(ct, err)
			assert.Greater(ct, resp.Hits.Total.Value, 0, "no docs from churn pod %s yet", newPodName)
		}, 5*time.Minute, 5*time.Second, "logs from churn pod %s never appeared in ES", newPodName)

		*dst = time.Since(deployTime)
		t.Logf("pod churn: first log from %s in ES after %s total (pod-ready: %s, ES-index lag: %s)",
			newPodName,
			dst.Round(time.Millisecond),
			podReadyTime.Sub(deployTime).Round(time.Millisecond),
			time.Since(podReadyTime).Round(time.Millisecond),
		)
	}
}

// resourceSample is a point-in-time CPU/memory reading for one container.
type resourceSample struct {
	cpuMilliCores float64 // milliCPU (1000 = 1 core)
	memMiB        float64 // working-set in MiB
}

// bgSampler polls the kubelet /stats/summary endpoint in a background goroutine.
// Readings accumulate while ingestion is active; averages are written to dst in
// k8sStepStopResourceSampler. Log messages are buffered (not written directly to
// t.Logf) so they can be flushed safely after the goroutine exits.
type bgSampler struct {
	done      chan struct{}
	mu        sync.Mutex
	logs      []string
	nReadings int
	totalCPU  float64
	totalMem  float64
}

// k8sStepStartResourceSampler resolves the agent pod/node, then launches a background
// goroutine that polls kubelet every 5 s. Insert this step BEFORE the ingestion check
// so readings cover the active ingestion period, not idle time after it.
func k8sStepStartResourceSampler(dst *resourceSample, podLabelSelector, containerName string) (*bgSampler, k8sTestStep) {
	s := &bgSampler{done: make(chan struct{})}

	start := func(t *testing.T, ctx context.Context, kCtx k8sContext, namespace string) {
		var podName, nodeName string
		require.EventuallyWithT(t, func(ct *assert.CollectT) {
			pods, err := kCtx.clientSet.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{
				LabelSelector: podLabelSelector,
			})
			if !assert.NoError(ct, err, "list agent pods") || !assert.NotEmpty(ct, pods.Items, "no agent pods") {
				return
			}
			pod := pods.Items[0]
			if !assert.NotEmpty(ct, pod.Spec.NodeName, "agent pod has no node") {
				return
			}
			podName = pod.Name
			nodeName = pod.Spec.NodeName
		}, 30*time.Second, 2*time.Second, "agent pod for %s not ready", podLabelSelector)

		s.mu.Lock()
		s.logs = append(s.logs, fmt.Sprintf("resource sampler: started for pod %s on node %s", podName, nodeName))
		s.mu.Unlock()

		go func() {
			record := func() {
				cpu, mem, ok := kubeletPollOnce(ctx, kCtx, namespace, podName, nodeName, containerName)
				if !ok {
					return
				}
				cpuM := float64(cpu) / 1e6
				memM := float64(mem) / (1024 * 1024)
				s.mu.Lock()
				s.nReadings++
				n := s.nReadings
				s.totalCPU += cpuM
				s.totalMem += memM
				s.logs = append(s.logs, fmt.Sprintf("resource sample #%d: CPU=%.2f mCPU  Mem=%.1f MiB", n, cpuM, memM))
				s.mu.Unlock()
			}
			// Poll immediately so we always capture at least one reading even if
			// the ingestion check window is short.
			record()
			ticker := time.NewTicker(5 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-s.done:
					return
				case <-ticker.C:
					record()
				}
			}
		}()
	}

	return s, start
}

// k8sStepStopResourceSampler signals the background sampler to stop, flushes its
// buffered log messages to t, and writes the averaged CPU/memory into dst.
func k8sStepStopResourceSampler(s *bgSampler, dst *resourceSample) k8sTestStep {
	return func(t *testing.T, ctx context.Context, kCtx k8sContext, namespace string) {
		close(s.done)
		// Brief pause so the goroutine finishes its current iteration before we read.
		time.Sleep(200 * time.Millisecond)

		s.mu.Lock()
		defer s.mu.Unlock()
		for _, msg := range s.logs {
			t.Log(msg)
		}
		if s.nReadings > 0 {
			dst.cpuMilliCores = s.totalCPU / float64(s.nReadings)
			dst.memMiB = s.totalMem / float64(s.nReadings)
			t.Logf("resource sampler: average over %d readings — CPU=%.2f mCPU  Mem=%.1f MiB",
				s.nReadings, dst.cpuMilliCores, dst.memMiB)
		} else {
			t.Log("resource sampler: no readings obtained")
		}
	}
}

// kubelet /stats/summary minimal JSON shapes.
type kubeletStatsSummary struct {
	Pods []kubeletPodStats `json:"pods"`
}

type kubeletPodStats struct {
	PodRef     kubeletPodRef      `json:"podRef"`
	Containers []kubeletContStats `json:"containers"`
}

type kubeletPodRef struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
}

type kubeletContStats struct {
	Name   string             `json:"name"`
	CPU    *kubeletCPUStat    `json:"cpu,omitempty"`
	Memory *kubeletMemoryStat `json:"memory,omitempty"`
}

type kubeletCPUStat struct {
	UsageNanoCores uint64 `json:"usageNanoCores"`
}

type kubeletMemoryStat struct {
	WorkingSetBytes uint64 `json:"workingSetBytes"`
}

// kubeletPollOnce queries the kubelet /stats/summary proxy for the named container
// and returns its current CPU (nanocores) and memory (working-set bytes).
// Returns (0, 0, false) if the pod or container is not found or the reading is not yet available.
func kubeletPollOnce(ctx context.Context, kCtx k8sContext, namespace, podName, nodeName, containerName string) (cpuNano uint64, memBytes uint64, ok bool) {
	raw, err := kCtx.clientSet.CoreV1().RESTClient().
		Get().
		AbsPath(fmt.Sprintf("/api/v1/nodes/%s/proxy/stats/summary", nodeName)).
		DoRaw(ctx)
	if err != nil {
		return 0, 0, false
	}
	var summary kubeletStatsSummary
	if err := json.Unmarshal(raw, &summary); err != nil {
		return 0, 0, false
	}
	for _, ps := range summary.Pods {
		if ps.PodRef.Name != podName || ps.PodRef.Namespace != namespace {
			continue
		}
		for _, cs := range ps.Containers {
			if cs.Name != containerName {
				continue
			}
			if cs.CPU == nil || cs.CPU.UsageNanoCores == 0 {
				return 0, 0, false // rolling average not yet computed
			}
			var mem uint64
			if cs.Memory != nil {
				mem = cs.Memory.WorkingSetBytes
			}
			return cs.CPU.UsageNanoCores, mem, true
		}
	}
	return 0, 0, false
}
